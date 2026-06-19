import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import json
import re
import hashlib
import io
from pathlib import Path
from datetime import datetime, timedelta
import bcrypt
import smtplib
import secrets as _secrets_mod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import create_engine, text

st.set_page_config(page_title="Controle Financeiro", page_icon="💜", layout="wide")

BASE = Path(__file__).parent

DEFAULT_RULES = {
    "Transporte":        ["uber", "99app", "cabify", "99taxi"],
    "Alimentação":       ["ifood", "carrefour", "mercado", "supermercado", "restaurante", "padaria"],
    "Saúde":            ["farma", "drogaria", "honorato", "redepharma", "clinica", "hospital"],
    "Telefone/Internet": ["telefonica", "vivo", "claro", "tim"],
    "Dívidas/Boletos":  ["picpay", "realize", "banco csf", "pagamento de boleto"],
    "Investimento":     ["aplicação rdb", "aplicacao rdb"],
    "Ignorar":          [],
}

ALL_CATS = [
    "Transporte", "Alimentação", "Saúde", "Telefone/Internet",
    "Dívidas/Boletos", "Investimento", "Fatura Cartão",
    "Pix Enviado", "Entrada", "Resgate RDB", "Outros",
    "Ignorar", "Não categorizado",
]

# ── DB ────────────────────────────────────────────────────────────────────────
@st.cache_resource
def get_engine():
    return create_engine(st.secrets["DATABASE_URL"], pool_pre_ping=True)

def db_exec(sql: str, params: dict = None, fetch: bool = False):
    with get_engine().begin() as conn:
        result = conn.execute(text(sql), params or {})
        if fetch:
            rows = result.fetchall()
            return rows, list(result.keys())
    return [], []

def db_df(sql: str, params: dict = None) -> pd.DataFrame:
    with get_engine().connect() as conn:
        result = conn.execute(text(sql), params or {})
        rows = result.fetchall()
        cols = list(result.keys())
    return pd.DataFrame(rows, columns=cols)

@st.cache_resource
def db_init():
    with get_engine().begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS usuarios (
                nome TEXT PRIMARY KEY, pin_hash TEXT NOT NULL
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS transacoes (
                uid TEXT, usuario TEXT, data TEXT,
                valor REAL, descricao TEXT, categoria TEXT,
                PRIMARY KEY (uid, usuario)
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS orcamentos (
                categoria TEXT, mes TEXT, usuario TEXT, limite REAL,
                PRIMARY KEY (categoria, mes, usuario)
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS rendas (
                nome TEXT, usuario TEXT, mes TEXT, valor REAL,
                PRIMARY KEY (nome, usuario, mes)
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS historico (
                id SERIAL PRIMARY KEY,
                evento_id TEXT, uid TEXT, usuario TEXT,
                cat_antes TEXT, cat_depois TEXT, ts TEXT
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS preferencias (
                usuario TEXT, chave TEXT, valor TEXT,
                PRIMARY KEY (usuario, chave)
            )
        """))

def _migrar_rendas():
    """Migração única: adiciona coluna mes em rendas (schema antigo sem mes)."""
    try:
        with get_engine().begin() as conn:
            conn.execute(text("ALTER TABLE rendas ADD COLUMN IF NOT EXISTS mes TEXT DEFAULT ''"))
        with get_engine().begin() as conn:
            now_mes = datetime.now().strftime("%Y-%m")
            conn.execute(text(
                "UPDATE rendas SET mes = :m WHERE mes IS NULL OR mes = ''"
            ), {"m": now_mes})
        with get_engine().begin() as conn:
            has_mes_pk = conn.execute(text("""
                SELECT 1 FROM information_schema.key_column_usage
                WHERE table_name='rendas' AND column_name='mes'
                  AND constraint_name IN (
                      SELECT constraint_name FROM information_schema.table_constraints
                      WHERE table_name='rendas' AND constraint_type='PRIMARY KEY'
                  )
            """)).fetchone()
            if not has_mes_pk:
                conn.execute(text("ALTER TABLE rendas DROP CONSTRAINT IF EXISTS rendas_pkey"))
                conn.execute(text("ALTER TABLE rendas ADD PRIMARY KEY (nome, usuario, mes)"))
    except Exception:
        pass

def _migrar_auth():
    cols = [
        ("senha_hash",         "TEXT"),
        ("email",              "TEXT"),
        ("email_verificado",   "BOOLEAN DEFAULT TRUE"),
        ("token_verificacao",  "TEXT"),
        ("token_reset",        "TEXT"),
        ("token_reset_expira", "TEXT"),
        ("tentativas",         "INT DEFAULT 0"),
        ("bloqueado_ate",      "TEXT"),
        ("ultimo_acesso",      "TEXT"),
    ]
    with get_engine().begin() as conn:
        for col, defn in cols:
            try:
                conn.execute(text(f"ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS {col} {defn}"))
            except Exception:
                pass
        try:
            conn.execute(text("ALTER TABLE usuarios ALTER COLUMN pin_hash DROP NOT NULL"))
        except Exception:
            pass

# ── Auth ──────────────────────────────────────────────────────────────────────
_MAX_TENTATIVAS    = 5
_BLOQUEIO_MINUTOS  = 15

def _has_email_config() -> bool:
    try:
        return bool(st.secrets.get("EMAIL_USER") and st.secrets.get("EMAIL_PASSWORD"))
    except Exception:
        return False

def _hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

def _check_senha(senha: str, senha_hash: str) -> bool:
    try:
        return bcrypt.checkpw(senha.encode(), senha_hash.encode())
    except Exception:
        return False

def _hash_pin_legacy(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def _gerar_token(n: int = 6) -> str:
    return "".join(_secrets_mod.choice("0123456789") for _ in range(n))

def user_exists(nome: str) -> bool:
    rows, _ = db_exec("SELECT 1 FROM usuarios WHERE nome=:n", {"n": nome}, fetch=True)
    return bool(rows)

def get_user(nome: str):
    rows, cols = db_exec("SELECT * FROM usuarios WHERE nome=:n", {"n": nome}, fetch=True)
    return dict(zip(cols, rows[0])) if rows else None

def verify_credenciais(nome: str, senha: str):
    """Retorna (ok: bool, is_legacy: bool)."""
    user = get_user(nome)
    if not user:
        return False, False
    if user.get("senha_hash"):
        return _check_senha(senha, user["senha_hash"]), False
    if user.get("pin_hash"):
        return user["pin_hash"] == _hash_pin_legacy(senha), True
    return False, False

def _check_bloqueio(nome: str):
    """Retorna (bloqueado: bool, minutos_restantes: int)."""
    user = get_user(nome)
    if not user or not user.get("bloqueado_ate"):
        return False, 0
    bloqueado_ate = datetime.fromisoformat(user["bloqueado_ate"])
    if datetime.now() < bloqueado_ate:
        mins = int((bloqueado_ate - datetime.now()).total_seconds() / 60) + 1
        return True, mins
    db_exec("UPDATE usuarios SET tentativas=0, bloqueado_ate=NULL WHERE nome=:n", {"n": nome})
    return False, 0

def _registrar_falha(nome: str):
    user = get_user(nome)
    if not user:
        return
    tentativas = (user.get("tentativas") or 0) + 1
    if tentativas >= _MAX_TENTATIVAS:
        bloqueado_ate = (datetime.now() + timedelta(minutes=_BLOQUEIO_MINUTOS)).isoformat()
        db_exec(
            "UPDATE usuarios SET tentativas=:t, bloqueado_ate=:b WHERE nome=:n",
            {"t": tentativas, "b": bloqueado_ate, "n": nome}
        )
    else:
        db_exec("UPDATE usuarios SET tentativas=:t WHERE nome=:n", {"t": tentativas, "n": nome})

def _resetar_falhas(nome: str):
    db_exec("UPDATE usuarios SET tentativas=0, bloqueado_ate=NULL WHERE nome=:n", {"n": nome})

def _registrar_acesso(nome: str):
    ts = datetime.now().strftime("%d/%m/%Y às %H:%M")
    db_exec("UPDATE usuarios SET ultimo_acesso=:ts WHERE nome=:n", {"ts": ts, "n": nome})

def create_user(nome: str, senha: str, email: str = ""):
    email_verificado = not bool(email) or not _has_email_config()
    token = _gerar_token() if (email and _has_email_config()) else None
    db_exec("""
        INSERT INTO usuarios (nome, senha_hash, email, email_verificado, token_verificacao, tentativas)
        VALUES (:n, :s, :e, :ev, :tv, 0)
        ON CONFLICT (nome) DO NOTHING
    """, {"n": nome, "s": _hash_senha(senha), "e": email or None,
          "ev": email_verificado, "tv": token})
    return token

def upgrade_legacy_user(nome: str, nova_senha: str):
    db_exec(
        "UPDATE usuarios SET senha_hash=:s, pin_hash=NULL WHERE nome=:n",
        {"s": _hash_senha(nova_senha), "n": nome}
    )

def verificar_token_email(nome: str, token: str) -> bool:
    rows, _ = db_exec(
        "SELECT 1 FROM usuarios WHERE nome=:n AND token_verificacao=:t",
        {"n": nome, "t": token}, fetch=True
    )
    if rows:
        db_exec(
            "UPDATE usuarios SET email_verificado=TRUE, token_verificacao=NULL WHERE nome=:n",
            {"n": nome}
        )
    return bool(rows)

def solicitar_reset(email: str):
    """Retorna (nome, token) ou None se email não encontrado."""
    rows, _ = db_exec("SELECT nome FROM usuarios WHERE email=:e", {"e": email}, fetch=True)
    if not rows:
        return None
    nome  = rows[0][0]
    token = _gerar_token()
    expira = (datetime.now() + timedelta(minutes=_BLOQUEIO_MINUTOS)).isoformat()
    db_exec(
        "UPDATE usuarios SET token_reset=:t, token_reset_expira=:e WHERE nome=:n",
        {"t": token, "e": expira, "n": nome}
    )
    return nome, token

def verificar_token_reset(nome: str, token: str) -> bool:
    rows, _ = db_exec(
        "SELECT token_reset_expira FROM usuarios WHERE nome=:n AND token_reset=:t",
        {"n": nome, "t": token}, fetch=True
    )
    if not rows:
        return False
    return datetime.now() < datetime.fromisoformat(rows[0][0])

def alterar_senha(nome: str, nova_senha: str):
    db_exec(
        "UPDATE usuarios SET senha_hash=:s, token_reset=NULL, token_reset_expira=NULL WHERE nome=:n",
        {"s": _hash_senha(nova_senha), "n": nome}
    )

def _enviar_email(dest: str, assunto: str, corpo_html: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = assunto
        msg["From"]    = st.secrets["EMAIL_USER"]
        msg["To"]      = dest
        msg.attach(MIMEText(corpo_html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as srv:
            srv.login(st.secrets["EMAIL_USER"], st.secrets["EMAIL_PASSWORD"])
            srv.sendmail(st.secrets["EMAIL_USER"], dest, msg.as_string())
        return True
    except Exception:
        return False

def enviar_verificacao(email: str, token: str) -> bool:
    corpo = f"""
    <div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px">
      <h2 style="color:#7c3aed">💜 Controle Financeiro</h2>
      <p>Seu código de verificação é:</p>
      <div style="font-size:38px;font-weight:bold;letter-spacing:10px;color:#7c3aed;
                  padding:20px;background:#f5f3ff;border-radius:10px;text-align:center">
        {token}
      </div>
      <p style="color:#888;font-size:12px;margin-top:16px">
        Válido por 15 minutos. Ignore se não criou uma conta.
      </p>
    </div>"""
    return _enviar_email(email, "Código de verificação — Controle Financeiro", corpo)

def enviar_reset(email: str, token: str) -> bool:
    corpo = f"""
    <div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px">
      <h2 style="color:#7c3aed">💜 Controle Financeiro</h2>
      <p>Seu código para redefinir a senha é:</p>
      <div style="font-size:38px;font-weight:bold;letter-spacing:10px;color:#7c3aed;
                  padding:20px;background:#f5f3ff;border-radius:10px;text-align:center">
        {token}
      </div>
      <p style="color:#888;font-size:12px;margin-top:16px">
        Válido por 15 minutos. Ignore se não solicitou redefinição de senha.
      </p>
    </div>"""
    return _enviar_email(email, "Redefinir senha — Controle Financeiro", corpo)

# ── Rules per user ────────────────────────────────────────────────────────────
@st.cache_data
def load_rules(usuario: str) -> dict:
    rows, _ = db_exec(
        "SELECT valor FROM preferencias WHERE usuario=:u AND chave='regras'",
        {"u": usuario}, fetch=True
    )
    return json.loads(rows[0][0]) if rows else DEFAULT_RULES.copy()

def save_rules(rules: dict, usuario: str):
    db_exec("""
        INSERT INTO preferencias (usuario, chave, valor) VALUES (:u, 'regras', :v)
        ON CONFLICT (usuario, chave) DO UPDATE SET valor=EXCLUDED.valor
    """, {"u": usuario, "v": json.dumps(rules, ensure_ascii=False)})
    load_rules.clear()

def backup_rules(rules: dict, usuario: str):
    db_exec("""
        INSERT INTO preferencias (usuario, chave, valor) VALUES (:u, 'regras_backup', :v)
        ON CONFLICT (usuario, chave) DO UPDATE SET valor=EXCLUDED.valor
    """, {"u": usuario, "v": json.dumps(rules, ensure_ascii=False)})
    has_rules_backup.clear()

@st.cache_data
def has_rules_backup(usuario: str) -> bool:
    rows, _ = db_exec(
        "SELECT 1 FROM preferencias WHERE usuario=:u AND chave='regras_backup'",
        {"u": usuario}, fetch=True
    )
    return bool(rows)

def undo_rules(usuario: str) -> bool:
    rows, _ = db_exec(
        "SELECT valor FROM preferencias WHERE usuario=:u AND chave='regras_backup'",
        {"u": usuario}, fetch=True
    )
    if not rows:
        return False
    db_exec("""
        INSERT INTO preferencias (usuario, chave, valor) VALUES (:u, 'regras', :v)
        ON CONFLICT (usuario, chave) DO UPDATE SET valor=EXCLUDED.valor
    """, {"u": usuario, "v": rows[0][0]})
    db_exec("DELETE FROM preferencias WHERE usuario=:u AND chave='regras_backup'", {"u": usuario})
    load_rules.clear()
    has_rules_backup.clear()
    return True

@st.cache_data
def has_historico(usuario: str) -> bool:
    rows, _ = db_exec("SELECT 1 FROM historico WHERE usuario=:u LIMIT 1", {"u": usuario}, fetch=True)
    return bool(rows)

# ── Fetch (cached) ────────────────────────────────────────────────────────────
@st.cache_data
def fetch_data(usuario: str) -> pd.DataFrame:
    df = db_df(
        "SELECT uid, data, valor, descricao, categoria FROM transacoes WHERE usuario=:u ORDER BY data DESC",
        {"u": usuario}
    )
    if not df.empty:
        df["data"]  = pd.to_datetime(df["data"])
        df["valor"] = df["valor"].astype(float)
    return df

@st.cache_data
def fetch_rendas(usuario: str, mes: str) -> pd.DataFrame:
    rows, _ = db_exec(
        "SELECT nome, valor FROM rendas WHERE usuario=:u AND mes=:m ORDER BY nome",
        {"u": usuario, "m": mes}, fetch=True
    )
    if rows:
        return pd.DataFrame(rows, columns=["Fonte de renda", "Valor (R$)"])
    return pd.DataFrame(columns=["Fonte de renda", "Valor (R$)"])

@st.cache_data
def fetch_orcamentos(mes: str, usuario: str) -> dict:
    rows, _ = db_exec(
        "SELECT categoria, limite FROM orcamentos WHERE mes=:m AND usuario=:u",
        {"m": mes, "u": usuario}, fetch=True
    )
    return {r[0]: float(r[1]) for r in rows} if rows else {}

# ── Write ─────────────────────────────────────────────────────────────────────
def save_rendas(df: pd.DataFrame, usuario: str, mes: str):
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM rendas WHERE usuario=:u AND mes=:m"), {"u": usuario, "m": mes})
        for _, row in df.iterrows():
            nome_val = row["Fonte de renda"]
            if pd.notna(nome_val) and str(nome_val).strip():
                conn.execute(
                    text("INSERT INTO rendas (nome, usuario, mes, valor) VALUES (:n, :u, :m, :v)"),
                    {"n": str(nome_val).strip(), "u": usuario, "m": mes, "v": float(row["Valor (R$)"])}
                )

def save_orcamentos(values: dict, mes: str, usuario: str):
    with get_engine().begin() as conn:
        for cat, limite in values.items():
            if limite > 0:
                conn.execute(text("""
                    INSERT INTO orcamentos (categoria, mes, usuario, limite)
                    VALUES (:c, :m, :u, :l)
                    ON CONFLICT (categoria, mes, usuario) DO UPDATE SET limite=EXCLUDED.limite
                """), {"c": cat, "m": mes, "u": usuario, "l": limite})
            else:
                conn.execute(
                    text("DELETE FROM orcamentos WHERE categoria=:c AND mes=:m AND usuario=:u"),
                    {"c": cat, "m": mes, "u": usuario}
                )

def import_rows(rows: list[dict], usuario: str) -> int:
    new = 0
    with get_engine().begin() as conn:
        for r in rows:
            result = conn.execute(text("""
                INSERT INTO transacoes (uid, usuario, data, valor, descricao, categoria)
                VALUES (:uid, :u, :data, :valor, :descricao, :categoria)
                ON CONFLICT (uid, usuario) DO NOTHING
            """), {**r, "u": usuario})
            new += result.rowcount
    return new

def add_manual_transaction(descricao: str, valor: float, categoria: str, periodo: str, usuario: str):
    uid  = f"manual_{datetime.now().isoformat()}"
    now  = datetime.now()
    data = now.strftime("%Y-%m-%d") if periodo == now.strftime("%Y-%m") else \
           pd.Period(periodo, freq="M").start_time.strftime("%Y-%m-%d")
    db_exec("""
        INSERT INTO transacoes (uid, usuario, data, valor, descricao, categoria)
        VALUES (:uid, :u, :data, :valor, :descricao, :cat)
        ON CONFLICT (uid, usuario) DO NOTHING
    """, {"uid": uid, "u": usuario, "data": data, "valor": -abs(valor),
          "descricao": descricao, "cat": categoria})

def save_categorias(changes: list, usuario: str):
    if not changes:
        return
    evento_id = datetime.now().isoformat()
    with get_engine().begin() as conn:
        for uid, nova_cat in changes:
            row = conn.execute(
                text("SELECT categoria FROM transacoes WHERE uid=:uid AND usuario=:u"),
                {"uid": uid, "u": usuario}
            ).fetchone()
            cat_antes = row[0] if row else ""
            conn.execute(text("""
                INSERT INTO historico (evento_id, uid, usuario, cat_antes, cat_depois, ts)
                VALUES (:eid, :uid, :u, :ca, :cd, :ts)
            """), {"eid": evento_id, "uid": uid, "u": usuario,
                   "ca": cat_antes, "cd": nova_cat, "ts": evento_id})
            conn.execute(
                text("UPDATE transacoes SET categoria=:cat WHERE uid=:uid AND usuario=:u"),
                {"cat": nova_cat, "uid": uid, "u": usuario}
            )
    has_historico.clear()

def undo_last_tx(usuario: str) -> int:
    with get_engine().begin() as conn:
        row = conn.execute(
            text("SELECT evento_id FROM historico WHERE usuario=:u ORDER BY id DESC LIMIT 1"),
            {"u": usuario}
        ).fetchone()
        if not row:
            return 0
        evento_id = row[0]
        changes = conn.execute(
            text("SELECT uid, cat_antes FROM historico WHERE evento_id=:eid AND usuario=:u"),
            {"eid": evento_id, "u": usuario}
        ).fetchall()
        for uid, cat_antes in changes:
            conn.execute(
                text("UPDATE transacoes SET categoria=:cat WHERE uid=:uid AND usuario=:u"),
                {"cat": cat_antes, "uid": uid, "u": usuario}
            )
        conn.execute(
            text("DELETE FROM historico WHERE evento_id=:eid AND usuario=:u"),
            {"eid": evento_id, "u": usuario}
        )
    has_historico.clear()
    return len(changes)

def delete_categoria_completa(cat_name: str, rules: dict, usuario: str) -> int:
    backup_rules(rules, usuario)
    if cat_name in rules:
        del rules[cat_name]
        save_rules(rules, usuario)
    with get_engine().begin() as conn:
        affected = conn.execute(
            text("SELECT uid FROM transacoes WHERE categoria=:c AND usuario=:u"),
            {"c": cat_name, "u": usuario}
        ).fetchall()
        if affected:
            evento_id = datetime.now().isoformat()
            for (uid,) in affected:
                conn.execute(text("""
                    INSERT INTO historico (evento_id, uid, usuario, cat_antes, cat_depois, ts)
                    VALUES (:eid, :uid, :u, :ca, 'Não categorizado', :ts)
                """), {"eid": evento_id, "uid": uid, "u": usuario, "ca": cat_name, "ts": evento_id})
                conn.execute(
                    text("UPDATE transacoes SET categoria='Não categorizado' WHERE uid=:uid AND usuario=:u"),
                    {"uid": uid, "u": usuario}
                )
    return len(affected)

def delete_transaction(uid: str, usuario: str):
    db_exec("DELETE FROM transacoes WHERE uid=:uid AND usuario=:u", {"uid": uid, "u": usuario})

def delete_renda(nome: str, usuario: str, mes: str):
    db_exec("DELETE FROM rendas WHERE nome=:n AND usuario=:u AND mes=:m",
            {"n": nome, "u": usuario, "m": mes})
    fetch_rendas.clear()

def add_renda(nome: str, valor: float, usuario: str, mes: str):
    db_exec("""
        INSERT INTO rendas (nome, usuario, mes, valor) VALUES (:n, :u, :m, :v)
        ON CONFLICT (nome, usuario, mes) DO UPDATE SET valor=EXCLUDED.valor
    """, {"n": nome, "u": usuario, "m": mes, "v": valor})
    fetch_rendas.clear()

def delete_all_data(usuario: str):
    with get_engine().begin() as conn:
        for tbl in ["transacoes", "orcamentos", "rendas", "historico"]:
            conn.execute(text(f"DELETE FROM {tbl} WHERE usuario=:u"), {"u": usuario})

# ── Parse ─────────────────────────────────────────────────────────────────────
def parse_brl_input(s: str) -> float:
    s = s.strip().replace("R$", "").replace(" ", "")
    if not s:
        return 0.0
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return max(0.0, float(s))
    except ValueError:
        return 0.0

def budget_input(label: str, key: str, db_value: float) -> float:
    init_key = f"_init_{key}"
    if st.session_state.get(init_key) != db_value:
        st.session_state[init_key] = db_value
        st.session_state[key] = f"{db_value:.2f}".replace(".", ",") if db_value > 0 else ""
    raw = st.text_input(label, key=key, placeholder="0,00", label_visibility="collapsed")
    return parse_brl_input(raw)

def categorize(desc: str, valor: float, rules: dict) -> str:
    d = desc.lower()
    if valor > 0:
        return "Resgate RDB" if "resgate rdb" in d else "Entrada"
    if "pagamento de fatura" in d:
        return "Fatura Cartão"
    for cat, kws in rules.items():
        if any(kw in d for kw in kws):
            return cat
    if "enviada" in d or "enviado" in d:
        return "Pix Enviado"
    return "Não categorizado"

def get_tipo(desc: str) -> str:
    d = desc.lower()
    if "débito via nupay" in d or "debito via nupay" in d:
        return "Débito"
    if "pagamento de boleto" in d:
        return "Boleto"
    if "pagamento de fatura" in d:
        return "Fatura Cartão"
    if "enviada" in d or "enviado" in d:
        return "Pix Enviado"
    if "recebida" in d or "recebido" in d:
        return "Pix Recebido"
    if "aplicação rdb" in d or "aplicacao rdb" in d or "resgate rdb" in d:
        return "RDB"
    return "Outros"

def extract_merchant(desc: str) -> str:
    for pat in [
        r"Compra no débito via NuPay - (.+)",
        r"Transferência enviada pelo Pix - ([^-•]+)",
        r"Transferência recebida pelo Pix - ([^-•]+)",
        r"Transferência Recebida - ([^-•]+)",
        r"Pagamento de boleto efetuado - (.+)",
    ]:
        m = re.match(pat, desc, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return desc.split(" - ")[0] if " - " in desc else desc

# ── Parsers multi-banco ───────────────────────────────────────────────────────
def _decode(raw: bytes) -> str:
    for enc in ["utf-8-sig", "utf-8", "latin-1", "cp1252"]:
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode("latin-1", errors="replace")

def _to_float(s) -> float | None:
    s = re.sub(r"[R$\s]", "", str(s)).strip()
    if not s or s in ("-", "nan", ""):
        return None
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None

def _to_date(s) -> str | None:
    s = str(s).strip()
    if re.match(r"^\d{8}", s):
        try:
            return pd.to_datetime(s[:8], format="%Y%m%d").strftime("%Y-%m-%d")
        except Exception:
            pass
    for fmt in ["%d/%m/%Y", "%Y-%m-%d", "%d/%m/%y", "%d-%m-%Y", "%Y/%m/%d"]:
        try:
            return pd.to_datetime(s[:10], format=fmt).strftime("%Y-%m-%d")
        except Exception:
            pass
    return None

def _uid(prefix: str, *parts) -> str:
    h = hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()[:12]
    return f"{prefix}_{h}"

def _find_col(cols: list[str], keywords: list[str]) -> str | None:
    for kw in keywords:
        for col in cols:
            if kw.lower() in col.lower():
                return col
    return None

def _parse_nubank(text: str, rules: dict) -> list[dict]:
    df = pd.read_csv(io.StringIO(text), dtype=str)
    if len(df.columns) < 4:
        return []
    df.columns = ["Data", "Valor", "Identificador", "Descrição"]
    df["Valor"] = pd.to_numeric(df["Valor"], errors="coerce")
    df = df.dropna(subset=["Valor"])
    df = df[~df["Descrição"].str.startswith("Valor adicionado", na=False)].copy()
    rows, seen = [], {}
    for _, r in df.iterrows():
        base = str(r["Identificador"]) + ("_p" if r["Valor"] > 0 else "_n")
        seen[base] = seen.get(base, 0) + 1
        uid = f"nu_{base}_{seen[base]}" if seen[base] > 1 else f"nu_{base}"
        d = _to_date(r["Data"])
        if d is None:
            continue
        rows.append({
            "uid": uid, "data": d, "valor": float(r["Valor"]),
            "descricao": r["Descrição"],
            "categoria": categorize(r["Descrição"], r["Valor"], rules),
        })
    return rows

def _parse_ofx(text: str, rules: dict) -> list[dict]:
    rows = []
    for block in re.findall(r"<STMTTRN>(.*?)</STMTTRN>", text, re.DOTALL | re.IGNORECASE):
        def get(tag):
            m = re.search(rf"<{tag}>\s*([^\n<]+)", block, re.IGNORECASE)
            return m.group(1).strip() if m else ""
        dtposted = get("DTPOSTED") or get("DTTRADE")
        trnamt   = get("TRNAMT")
        fitid    = get("FITID")
        memo     = get("MEMO") or get("NAME") or get("TRNTYPE")
        data  = _to_date(dtposted)
        valor = _to_float(trnamt)
        if data is None or valor is None:
            continue
        uid = f"ofx_{fitid}" if fitid else _uid("ofx", data, valor, memo)
        rows.append({
            "uid": uid, "data": data, "valor": valor,
            "descricao": memo,
            "categoria": categorize(memo, valor, rules),
        })
    return rows

def _parse_debit_credit(text: str, sep: str, rules: dict) -> list[dict]:
    df = pd.read_csv(io.StringIO(text), sep=sep, dtype=str, skipinitialspace=True)
    df.columns = [c.strip() for c in df.columns]
    cols = list(df.columns)
    col_data = _find_col(cols, ["data", "dt", "date"])
    col_hist = _find_col(cols, ["histórico", "historico", "descrição", "descricao",
                                 "memo", "lançamento", "lancamento", "detalhe"])
    col_cred = _find_col(cols, ["crédito", "credito", "créd", "entrada"])
    col_deb  = _find_col(cols, ["débito", "debito", "déb", "saída", "saida"])
    if not col_data:
        return []
    rows = []
    for _, r in df.iterrows():
        data = _to_date(r.get(col_data, ""))
        if data is None:
            continue
        desc = str(r.get(col_hist, "")).strip() if col_hist else ""
        cred = _to_float(r.get(col_cred, "")) if col_cred else None
        deb  = _to_float(r.get(col_deb, ""))  if col_deb  else None
        if cred and cred > 0:
            valor = cred
        elif deb and deb > 0:
            valor = -deb
        else:
            continue
        rows.append({
            "uid": _uid("csv", data, valor, desc),
            "data": data, "valor": valor, "descricao": desc,
            "categoria": categorize(desc, valor, rules),
        })
    return rows

def _parse_generic(text: str, sep: str, rules: dict) -> list[dict]:
    df = pd.read_csv(io.StringIO(text), sep=sep, dtype=str, skipinitialspace=True)
    df.columns = [c.strip() for c in df.columns]
    cols = list(df.columns)
    col_data  = _find_col(cols, ["data", "dt", "date"])
    col_hist  = _find_col(cols, ["descrição", "descricao", "histórico", "historico",
                                  "título", "titulo", "memo", "lançamento", "lancamento"])
    col_cred  = _find_col(cols, ["crédito", "credito", "créd", "entrada"])
    col_deb   = _find_col(cols, ["débito", "debito", "déb", "saída", "saida"])
    col_valor = _find_col(cols, ["valor", "value", "amount", "vl", "quantia"])
    if not col_data or not (col_valor or (col_cred and col_deb)):
        return []
    rows = []
    for _, r in df.iterrows():
        data = _to_date(r.get(col_data, ""))
        if data is None:
            continue
        desc = str(r.get(col_hist, "")).strip() if col_hist else ""
        if col_cred and col_deb:
            cred = _to_float(r.get(col_cred, ""))
            deb  = _to_float(r.get(col_deb, ""))
            if cred and cred > 0:
                valor = cred
            elif deb and deb > 0:
                valor = -deb
            else:
                continue
        else:
            valor = _to_float(r.get(col_valor, ""))
            if valor is None:
                continue
        rows.append({
            "uid": _uid("csv", data, valor, desc),
            "data": data, "valor": valor, "descricao": desc,
            "categoria": categorize(desc, valor, rules),
        })
    return rows

def parse_file(file, rules: dict) -> tuple[list[dict], str]:
    """Auto-detecta formato e parseia. Retorna (rows, nome_do_banco)."""
    raw  = file.read()
    text = _decode(raw)

    # OFX / QFX
    header = text[:2000].upper()
    if "OFXHEADER" in header or "<STMTTRN>" in header or ("<OFX>" in header and "TRNAMT" in header):
        rows = _parse_ofx(text, rules)
        return rows, "OFX"

    # CSV — tenta vírgula, ponto-e-vírgula, tab
    for sep in [",", ";", "\t"]:
        try:
            sample = pd.read_csv(io.StringIO(text), sep=sep, nrows=5, dtype=str)
            if len(sample.columns) < 2:
                continue
            cols = [str(c).strip().lower() for c in sample.columns]

            # Nubank conta: 4 colunas com 'identificador'
            if len(sample.columns) == 4 and any("identif" in c for c in cols):
                rows = _parse_nubank(text, rules)
                return rows, "Nubank"

            # Crédito + Débito (Bradesco, Itaú, BB, Caixa, Santander…)
            has_cred = any("cr" in c and "dito" in c for c in cols)
            has_deb  = any(("d" in c and "bito" in c) or "saída" in c or "saida" in c for c in cols)
            if has_cred and has_deb:
                rows = _parse_debit_credit(text, sep, rules)
                if rows:
                    return rows, "Bradesco / Itaú / BB"

            # Genérico
            rows = _parse_generic(text, sep, rules)
            if rows:
                return rows, "CSV"
        except Exception:
            continue

    return [], "formato não reconhecido"

def brl(v: float) -> str:
    s = f"R$ {abs(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"-{s}" if v < 0 else s

# ── Login ─────────────────────────────────────────────────────────────────────
def _forca_senha(senha: str):
    score = 0
    if len(senha) >= 8:  score += 1
    if len(senha) >= 12: score += 1
    if re.search(r'[A-Z]', senha): score += 1
    if re.search(r'[a-z]', senha): score += 1
    if re.search(r'\d',    senha): score += 1
    if re.search(r'[^A-Za-z0-9]', senha): score += 1
    if score <= 2: return score, "Fraca",  "#ef4444"
    if score <= 4: return score, "Média",  "#f59e0b"
    return score, "Forte", "#22c55e"

def _barra_forca(senha: str, mostrar_dicas: bool = False):
    score, label, color = _forca_senha(senha)
    pct = int(score / 6 * 100)
    dicas = []
    if mostrar_dicas:
        if len(senha) < 8:              dicas.append("8+ caracteres")
        if not re.search(r'[A-Z]', senha): dicas.append("maiúscula")
        if not re.search(r'\d',    senha): dicas.append("número")
        if not re.search(r'[^A-Za-z0-9]', senha): dicas.append("símbolo")
    extra = f" — falta: {', '.join(dicas)}" if dicas else (" ✓" if score >= 5 else "")
    st.markdown(f"""<div style="margin:-8px 0 10px">
      <div style="background:#e2e8f0;border-radius:4px;height:6px">
        <div style="background:{color};width:{pct}%;height:6px;border-radius:4px;transition:width .3s"></div>
      </div>
      <div style="font-size:12px;color:{color};margin-top:3px">Força: <b>{label}</b>{extra}</div>
    </div>""", unsafe_allow_html=True)

def render_login():
    _, col, _ = st.columns([1, 1.5, 1])
    estado = st.session_state.get("auth_estado")

    with col:
        st.markdown("## 💜 Controle Financeiro")
        st.markdown("---")

        # ── Verificação de e-mail pós-cadastro ──────────────────────────────
        if estado == "verificando_email":
            nome  = st.session_state.get("auth_usuario_pendente", "")
            email = st.session_state.get("auth_email_pendente", "")
            st.info(f"📧 Código enviado para **{email}**. Verifique sua caixa de entrada.")
            with st.form("form_verif"):
                codigo = st.text_input("Código de 6 dígitos", max_chars=6, placeholder="000000")
                c1, c2 = st.columns(2)
                with c1:
                    verificar = st.form_submit_button("Verificar →", type="primary", use_container_width=True)
                with c2:
                    reenviar = st.form_submit_button("Reenviar", use_container_width=True)
            if verificar:
                if verificar_token_email(nome, codigo.strip()):
                    _resetar_falhas(nome)
                    _registrar_acesso(nome)
                    st.session_state["usuario"] = nome
                    for k in ["auth_estado", "auth_usuario_pendente", "auth_email_pendente"]:
                        st.session_state.pop(k, None)
                    st.rerun()
                else:
                    st.error("Código inválido. Tente novamente.")
            if reenviar:
                user = get_user(nome)
                if user and user.get("email"):
                    token = _gerar_token()
                    db_exec("UPDATE usuarios SET token_verificacao=:t WHERE nome=:n",
                            {"t": token, "n": nome})
                    enviar_verificacao(user["email"], token)
                    st.success("Código reenviado!")
            if st.button("← Voltar", use_container_width=True):
                for k in ["auth_estado", "auth_usuario_pendente", "auth_email_pendente"]:
                    st.session_state.pop(k, None)
                st.rerun()
            return

        # ── Upgrade de PIN legado → nova senha ──────────────────────────────
        if estado == "upgrade_legacy":
            nome = st.session_state.get("auth_usuario_pendente", "")
            st.success(f"Bem-vindo de volta, **{nome}**!")
            st.warning("Por segurança, crie uma nova senha para sua conta.")
            st.caption("Requisitos: mínimo 8 caracteres, pelo menos uma letra e um número.")
            with st.form("form_upgrade"):
                nova = st.text_input("Nova senha", type="password", placeholder="Mínimo 8 caracteres")
                conf = st.text_input("Confirmar senha", type="password")
                confirmar = st.form_submit_button("Confirmar →", type="primary", use_container_width=True)
            if confirmar:
                if len(nova) < 8:
                    st.error("A senha deve ter pelo menos 8 caracteres.")
                    _barra_forca(nova)
                elif not re.search(r'[A-Za-z]', nova):
                    st.error("A senha deve conter pelo menos uma letra.")
                elif nova != conf:
                    st.error("As senhas não coincidem.")
                else:
                    upgrade_legacy_user(nome, nova)
                    _registrar_acesso(nome)
                    st.session_state["usuario"] = nome
                    for k in ["auth_estado", "auth_usuario_pendente"]:
                        st.session_state.pop(k, None)
                    st.rerun()
            return

        # ── Reset de senha — código + nova senha ────────────────────────────
        if estado == "reset_codigo":
            nome  = st.session_state.get("auth_reset_nome", "")
            email = st.session_state.get("auth_reset_email", "")
            st.info(f"📧 Código enviado para **{email}**.")
            st.caption("Requisitos: mínimo 8 caracteres, pelo menos uma letra e um número.")
            with st.form("form_reset"):
                codigo = st.text_input("Código de 6 dígitos", max_chars=6, placeholder="000000")
                nova   = st.text_input("Nova senha", type="password", placeholder="Mínimo 8 caracteres")
                conf   = st.text_input("Confirmar nova senha", type="password")
                redefinir = st.form_submit_button("Redefinir senha →", type="primary", use_container_width=True)
            if redefinir:
                if not verificar_token_reset(nome, codigo.strip()):
                    st.error("Código inválido ou expirado.")
                elif len(nova) < 8:
                    st.error("A senha deve ter pelo menos 8 caracteres.")
                    _barra_forca(nova)
                elif nova != conf:
                    st.error("As senhas não coincidem.")
                else:
                    alterar_senha(nome, nova)
                    for k in ["auth_estado", "auth_reset_nome", "auth_reset_email"]:
                        st.session_state.pop(k, None)
                    st.success("Senha redefinida com sucesso! Faça login.")
                    st.rerun()
            if st.button("← Voltar", use_container_width=True):
                for k in ["auth_estado", "auth_reset_nome", "auth_reset_email"]:
                    st.session_state.pop(k, None)
                st.rerun()
            return

        # ── Tela principal ───────────────────────────────────────────────────
        modo = st.radio("", ["Entrar", "Criar conta", "Esqueci a senha"],
                        horizontal=True, label_visibility="collapsed")

        # ENTRAR
        if modo == "Entrar":
            with st.form("form_entrar"):
                nome  = st.text_input("Usuário", placeholder="ex: arthur")
                senha = st.text_input("Senha", type="password")
                entrar = st.form_submit_button("Entrar →", type="primary", use_container_width=True)
            if entrar:
                if not nome or not senha:
                    st.error("Preencha usuário e senha.")
                elif not user_exists(nome):
                    st.error("Usuário não encontrado.")
                else:
                    bloqueado, mins = _check_bloqueio(nome)
                    if bloqueado:
                        st.error(f"🔒 Conta bloqueada. Tente novamente em **{mins} minuto(s)**.")
                    else:
                        ok, is_legacy = verify_credenciais(nome, senha)
                        if not ok:
                            _registrar_falha(nome)
                            bloqueado2, _ = _check_bloqueio(nome)
                            if bloqueado2:
                                st.error(f"🔒 Conta bloqueada por {_BLOQUEIO_MINUTOS} minutos após múltiplas tentativas.")
                            else:
                                user = get_user(nome)
                                tentativas = user.get("tentativas", 0) if user else 0
                                restantes  = _MAX_TENTATIVAS - tentativas
                                st.error(f"Senha incorreta. {restantes} tentativa(s) restante(s).")
                        elif is_legacy:
                            _resetar_falhas(nome)
                            st.session_state["auth_estado"] = "upgrade_legacy"
                            st.session_state["auth_usuario_pendente"] = nome
                            st.rerun()
                        else:
                            user = get_user(nome)
                            if user and not user.get("email_verificado", True):
                                st.session_state["auth_estado"] = "verificando_email"
                                st.session_state["auth_usuario_pendente"] = nome
                                st.session_state["auth_email_pendente"] = user.get("email", "")
                                st.rerun()
                            else:
                                ult = user.get("ultimo_acesso") if user else None
                                _resetar_falhas(nome)
                                _registrar_acesso(nome)
                                st.session_state["usuario"] = nome
                                if ult:
                                    st.session_state["_ultimo_acesso"] = ult
                                st.rerun()

        # CRIAR CONTA
        elif modo == "Criar conta":
            st.caption("Requisitos de senha: 8+ caracteres, pelo menos uma letra e um número.")
            with st.form("form_cadastro"):
                nome  = st.text_input("Usuário", placeholder="ex: maria")
                email = st.text_input("E-mail", placeholder="seu@email.com")
                senha = st.text_input("Senha", type="password", placeholder="Mínimo 8 caracteres")
                conf  = st.text_input("Confirmar senha", type="password")
                criar = st.form_submit_button("Criar conta →", type="primary", use_container_width=True)
            if criar:
                if not nome:
                    st.error("Digite um nome de usuário.")
                elif len(nome) < 3:
                    st.error("Usuário deve ter pelo menos 3 caracteres.")
                elif email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                    st.error("E-mail inválido.")
                elif len(senha) < 8:
                    st.error("A senha deve ter pelo menos 8 caracteres.")
                    _barra_forca(senha)
                elif not re.search(r'[A-Za-z]', senha):
                    st.error("A senha deve conter pelo menos uma letra.")
                elif senha != conf:
                    st.error("As senhas não coincidem.")
                elif user_exists(nome):
                    st.error("Usuário já existe. Escolha outro nome.")
                else:
                    token = create_user(nome, senha, email)
                    if token and email and _has_email_config():
                        enviar_verificacao(email, token)
                        st.session_state["auth_estado"] = "verificando_email"
                        st.session_state["auth_usuario_pendente"] = nome
                        st.session_state["auth_email_pendente"] = email
                        st.rerun()
                    else:
                        _registrar_acesso(nome)
                        st.session_state["usuario"] = nome
                        st.rerun()

        # ESQUECI A SENHA
        else:
            if not _has_email_config():
                st.warning("Recuperação de senha por e-mail não está configurada neste momento.")
            else:
                with st.form("form_esqueci"):
                    email  = st.text_input("E-mail cadastrado", placeholder="seu@email.com")
                    enviar = st.form_submit_button("Enviar código →", type="primary", use_container_width=True)
                if enviar:
                    if not email:
                        st.error("Digite seu e-mail.")
                    else:
                        resultado = solicitar_reset(email)
                        if resultado:
                            nome_r, token_r = resultado
                            enviar_reset(email, token_r)
                            st.session_state["auth_estado"] = "reset_codigo"
                            st.session_state["auth_reset_nome"]  = nome_r
                            st.session_state["auth_reset_email"] = email
                            st.rerun()
                        else:
                            st.success("Se o e-mail estiver cadastrado, você receberá um código em breve.")

# ── Dashboard ─────────────────────────────────────────────────────────────────
def render_dashboard(df_all: pd.DataFrame, periodo_sel: str, cats_excluir: list,
                     usuario: str, user_cats: list):
    mask = df_all["data"].dt.to_period("M").astype(str) == periodo_sel
    view = df_all[mask & ~df_all["categoria"].isin(cats_excluir)].copy()
    view["tipo"] = view["descricao"].map(get_tipo)

    tipo_sel = st.radio(
        "Tipo de pagamento",
        ["Todos", "Pix Enviado", "Débito", "Boleto", "Pix Recebido", "Fatura Cartão", "RDB"],
        horizontal=True, key="tipo_filter",
    )
    if tipo_sel != "Todos":
        view = view[view["tipo"] == tipo_sel]
        if view.empty:
            st.warning(f"Nenhuma transação do tipo **{tipo_sel}** no período selecionado.")

    st.divider()
    entradas = view[view["valor"] > 0]["valor"].sum()
    saidas   = view[view["valor"] < 0]["valor"].sum()
    c1, c2, c3 = st.columns(3)
    c1.metric("💰 Entradas", brl(entradas))
    c2.metric("💸 Saídas",   brl(saidas))
    c3.metric("📊 Saldo",    brl(entradas + saidas))
    st.divider()

    gastos = view[view["valor"] < 0].copy()
    gastos["abs"] = gastos["valor"].abs()

    _chart_cfg = {"scrollZoom": False, "displayModeBar": False}

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Gastos por categoria")
        if not gastos.empty:
            by_cat = gastos.groupby("categoria")["abs"].sum().reset_index()
            by_cat.columns = ["Categoria", "Total"]
            by_cat_s = by_cat.sort_values("Total", ascending=False)
            fig = px.pie(by_cat_s, names="Categoria", values="Total", hole=0.45,
                         color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_traces(
                textposition="inside",
                texttemplate="<b>%{label}</b><br>%{percent}",
                hovertemplate="<b>%{label}</b><br>R$ %{value:,.2f}<extra></extra>",
            )
            fig.update_layout(
                showlegend=False, margin=dict(t=10, b=0),
                dragmode=False, clickmode="event",
            )
            st.plotly_chart(fig, use_container_width=True, config=_chart_cfg)
        else:
            st.info("Sem gastos registrados neste período.")

    with col2:
        st.subheader("Gastos por dia")
        if not gastos.empty:
            by_day = gastos.groupby(gastos["data"].dt.date)["abs"].sum().reset_index()
            by_day.columns = ["Data", "Total"]
            fig2 = px.bar(by_day, x="Data", y="Total", color_discrete_sequence=["#8b5cf6"])
            fig2.update_layout(
                xaxis_title="", yaxis_title="R$", margin=dict(t=10, b=0),
                dragmode=False,
            )
            st.plotly_chart(fig2, use_container_width=True, config=_chart_cfg)
        else:
            st.info("Sem gastos registrados neste período.")

    if not gastos.empty:
        meses_disp = df_all["data"].dt.to_period("M").nunique()
        if meses_disp > 1:
            st.subheader("⚠️ Acima da média histórica")
            media_hist = (
                df_all[df_all["valor"] < 0].copy()
                .assign(abs=lambda d: d["valor"].abs(),
                        mes=lambda d: d["data"].dt.to_period("M").astype(str))
                .groupby(["mes", "categoria"])["abs"].sum()
                .groupby("categoria").mean()
            )
            atual_cat = gastos.groupby("categoria")["abs"].sum()
            alertas = []
            for cat in atual_cat.index:
                if cat in media_hist.index:
                    media = media_hist[cat]
                    atual = atual_cat[cat]
                    if atual > media * 1.2:
                        alertas.append({"Categoria": cat, "Este mês": brl(atual),
                                        "Média histórica": brl(media),
                                        "Diferença": f"+{brl(atual - media)}"})
            if alertas:
                st.dataframe(pd.DataFrame(alertas), hide_index=True, use_container_width=True)
            else:
                st.success("Tudo dentro da média histórica!")

        st.subheader("Top 5 maiores gastos")
        top5 = gastos.nlargest(5, "abs")[["data", "abs", "descricao", "categoria"]].copy()
        top5["data"] = top5["data"].dt.strftime("%d/%m/%Y")
        top5["abs"]  = top5["abs"].map(brl)
        st.dataframe(top5.rename(columns={"data": "Data", "abs": "Valor",
                                           "descricao": "Descrição", "categoria": "Categoria"}),
                     hide_index=True, use_container_width=True)

    render_tx_fragment(df_all, periodo_sel, cats_excluir, usuario, user_cats)

# ── Orçamento ─────────────────────────────────────────────────────────────────
def render_orcamento(df_all: pd.DataFrame, usuario: str, user_cats: list):
    IGNORAR_CATS = {"Entrada", "Resgate RDB", "Fatura Cartão", "Investimento", "Ignorar"}

    now = datetime.now()
    mes_atual = now.strftime("%Y-%m")
    prox_mes  = f"{now.year}-{now.month + 1:02d}" if now.month < 12 else f"{now.year + 1}-01"
    nomes_mes = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]

    def fmt_mes(s: str) -> str:
        y, m = s.split("-")
        label = f"{nomes_mes[int(m)-1]}/{y}"
        if s == prox_mes:    label += "  —  planejamento"
        elif s == mes_atual: label += "  —  mês atual"
        return label

    meses_tx = sorted(df_all["data"].dt.to_period("M").astype(str).unique(), reverse=True) if not df_all.empty else []
    meses_opcoes = list(dict.fromkeys([prox_mes, mes_atual] + list(meses_tx)))
    idx_default  = meses_opcoes.index(mes_atual) if mes_atual in meses_opcoes else 0

    col_ms, _ = st.columns([2, 4])
    mes_orc = col_ms.selectbox("📅 Mês", meses_opcoes, index=idx_default,
                               format_func=fmt_mes, key="mes_orcamento")

    tem_dados = mes_orc in meses_tx
    eh_futuro = mes_orc > mes_atual

    if eh_futuro:
        st.info("📋 Planejamento futuro — nenhum gasto registrado ainda. Defina seu orçamento abaixo.")

    st.markdown("### 💵 Renda")
    rendas_df = fetch_rendas(usuario, mes_orc)

    if rendas_df.empty:
        mes_ant_r = str(pd.Period(mes_orc, freq="M") - 1)
        rendas_ant = fetch_rendas(usuario, mes_ant_r)
        if not rendas_ant.empty:
            if st.button(f"📋 Copiar rendas de {fmt_mes(mes_ant_r)} para este mês"):
                for _, row in rendas_ant.iterrows():
                    add_renda(str(row["Fonte de renda"]), float(row["Valor (R$)"]), usuario, mes_orc)
                fetch_rendas.clear()
                st.rerun()
        else:
            st.caption("Nenhuma renda cadastrada para este mês.")

    if not rendas_df.empty:
        rh1, rh2, rh3 = st.columns([3, 2, 1])
        rh1.markdown("**Fonte de renda**")
        rh2.markdown("**Valor**")
        rh3.markdown("")
        for _, row in rendas_df.iterrows():
            rc1, rc2, rc3 = st.columns([3, 2, 1])
            rc1.write(str(row["Fonte de renda"]))
            rc2.write(brl(float(row["Valor (R$)"])))
            if rc3.button("🗑️", key=f"del_renda_{mes_orc}_{row['Fonte de renda']}", help="Excluir"):
                delete_renda(str(row["Fonte de renda"]), usuario, mes_orc)
                st.rerun()

    with st.form("form_add_renda", clear_on_submit=True):
        st.markdown("**Adicionar renda**")
        fa1, fa2, fa3 = st.columns([3, 2, 1])
        new_nome  = fa1.text_input("Fonte", placeholder="ex: Salário", label_visibility="collapsed")
        new_val_s = fa2.text_input("Valor R$", placeholder="0,00", label_visibility="collapsed")
        if fa3.form_submit_button("➕"):
            if new_nome.strip():
                add_renda(new_nome.strip(), parse_brl_input(new_val_s), usuario, mes_orc)
                st.rerun()

    total_renda = float(rendas_df["Valor (R$)"].sum()) if not rendas_df.empty else 0.0

    if "hidden_orc" not in st.session_state:
        st.session_state["hidden_orc"] = set()
    hidden = st.session_state["hidden_orc"]

    mask = df_all["data"].dt.to_period("M").astype(str) == mes_orc
    gastos_mes = df_all[
        mask & (df_all["valor"] < 0)
        & ~df_all["categoria"].isin(IGNORAR_CATS)
        & ~df_all["categoria"].isin(hidden)
    ]
    total_gastos  = gastos_mes["valor"].sum()
    gasto_por_cat = gastos_mes.assign(abs=lambda d: d["valor"].abs()).groupby("categoria")["abs"].sum().to_dict()

    orcamentos   = fetch_orcamentos(mes_orc, usuario)
    total_orcado = sum(orcamentos.values())
    saldo_livre  = total_renda + total_gastos

    if eh_futuro and not orcamentos:
        meses_com_orc = [m for m in meses_tx if m <= mes_atual]
        if meses_com_orc:
            mes_ref = meses_com_orc[0]
            if st.button(f"📋 Copiar orçamento de {fmt_mes(mes_ref)} como ponto de partida"):
                orc_ref = fetch_orcamentos(mes_ref, usuario)
                if orc_ref:
                    save_orcamentos(orc_ref, mes_orc, usuario)
                    fetch_orcamentos.clear()
                    st.rerun()

    st.divider()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("💰 Renda",      brl(total_renda))
    c2.metric("📋 Orçado",     brl(total_orcado))
    if tem_dados:
        c3.metric("💸 Gasto",      brl(abs(total_gastos)))
        c4.metric("✅ Disponível", brl(saldo_livre),
                  delta=f"{saldo_livre/total_renda*100:.1f}% da renda" if total_renda > 0 else None)
    else:
        c3.metric("💸 Gasto",      "—")
        sobra = total_renda - total_orcado
        c4.metric("✅ Disponível", brl(sobra) if total_renda > 0 else "—")

    st.divider()
    st.markdown("### 📋 Categorias")
    st.caption("**Orçamento**: quanto você planeja gastar. **Gasto**: o que já saiu. Clique ➕ para lançar um gasto manual.")

    cats_expense  = [c for c in user_cats if c not in IGNORAR_CATS]
    cats_visiveis = [c for c in cats_expense if c not in hidden]
    new_values    = {}

    h1, h2, h3, h4, h5 = st.columns([3, 1.5, 1.5, 1.5, 1])
    h1.markdown("**Categoria**"); h2.markdown("**Orçamento**")
    h3.markdown("**Gasto**");     h4.markdown("**Restante**"); h5.markdown("**Ações**")
    st.markdown("---")

    for cat in cats_visiveis:
        gasto  = gasto_por_cat.get(cat, 0.0)
        limite = float(orcamentos.get(cat, 0.0))
        c1, c2, c3, c4, c5 = st.columns([3, 1.5, 1.5, 1.5, 1])

        with c1:
            st.write(f"**{cat}**")
            if limite > 0 and tem_dados:
                st.progress(min(gasto / limite, 1.0))
        with c2:
            new_values[cat] = budget_input("orc", f"orc_{cat}_{mes_orc}", limite)
        with c3:
            st.write(brl(gasto) if tem_dados else "—")
        with c4:
            lim = new_values[cat]
            if lim > 0:
                if tem_dados:
                    restante = lim - gasto
                    icon = "🔴" if restante < 0 else "🟡" if restante < lim * 0.2 else "🟢"
                    st.write(f"{icon} {brl(restante)}")
                else:
                    st.write(f"🟢 {brl(lim)}")
            else:
                st.write("—")
        with c5:
            btn1, btn2 = st.columns(2)
            if btn1.button("➕", key=f"show_add_{cat}_{mes_orc}", help="Adicionar gasto manual"):
                st.session_state[f"adding_{cat}"] = not st.session_state.get(f"adding_{cat}", False)
            if btn2.button("✕", key=f"hide_{cat}_{mes_orc}", help="Remover da visualização"):
                st.session_state["hidden_orc"].add(cat)
                st.rerun()

        if st.session_state.get(f"adding_{cat}", False):
            with st.form(key=f"form_add_{cat}", clear_on_submit=True):
                st.markdown(f"↳ **Adicionar gasto manual em {cat}**")
                mc1, mc2, mc3, mc4 = st.columns([3, 1.5, 1, 1])
                desc    = mc1.text_input("Descrição", placeholder="ex: Mercado em dinheiro")
                val_str = mc2.text_input("Valor R$",  placeholder="0,00")
                submitted = mc3.form_submit_button("✅ Adicionar")
                cancelled = mc4.form_submit_button("❌ Cancelar")
                if submitted:
                    add_manual_transaction(desc or f"Gasto manual — {cat}",
                                           parse_brl_input(val_str), cat, mes_orc, usuario)
                    fetch_data.clear()
                    st.session_state[f"adding_{cat}"] = False
                    st.rerun()
                if cancelled:
                    st.session_state[f"adding_{cat}"] = False
                    st.rerun()

    st.divider()
    if st.button("💾 Salvar orçamentos", type="primary"):
        save_orcamentos(new_values, mes_orc, usuario)
        fetch_orcamentos.clear()
        st.toast("Orçamentos salvos!", icon="✅")
        st.rerun()

    ocultas = st.session_state["hidden_orc"]
    if ocultas:
        with st.expander(f"Categorias ocultas ({len(ocultas)}) — clique para restaurar"):
            for h in list(ocultas):
                if st.button(f"＋ Mostrar {h}", key=f"restore_{h}"):
                    st.session_state["hidden_orc"].discard(h)
                    st.rerun()

    manuais = df_all[mask & df_all["uid"].str.startswith("manual_")].copy()
    if not manuais.empty:
        st.divider()
        with st.expander(f"🖊️ Gastos manuais registrados neste mês ({len(manuais)})"):
            g_header = st.columns([1.5, 3, 2, 1.5, 0.5])
            for col, label in zip(g_header, ["**Data**","**Descrição**","**Categoria**","**Valor**",""]):
                col.markdown(label)
            st.markdown("---")
            for _, row in manuais.sort_values("data").iterrows():
                g1, g2, g3, g4, g5 = st.columns([1.5, 3, 2, 1.5, 0.5])
                g1.write(row["data"].strftime("%d/%m/%Y"))
                g2.write(row["descricao"])
                g3.write(row["categoria"])
                g4.write(brl(row["valor"]))
                if g5.button("🗑️", key=f"del_manual_{row['uid']}", help="Remover"):
                    delete_transaction(row["uid"], usuario)
                    fetch_data.clear()
                    st.rerun()

# ── Histórico ─────────────────────────────────────────────────────────────────
def render_historico(df_all: pd.DataFrame, user_cats: list):
    st.subheader("Comparativo histórico")
    if df_all["data"].dt.to_period("M").nunique() < 2:
        st.info("Importe pelo menos 2 meses de extrato para ver o comparativo.")
        return

    gastos = df_all[df_all["valor"] < 0].copy()
    gastos["abs"] = gastos["valor"].abs()
    gastos["mes"] = gastos["data"].dt.to_period("M").astype(str)

    cats_sel = st.multiselect(
        "Categorias para comparar", options=user_cats,
        default=[c for c in ["Transporte","Alimentação","Saúde","Telefone/Internet","Dívidas/Boletos"] if c in user_cats],
    )
    if cats_sel:
        gastos = gastos[gastos["categoria"].isin(cats_sel)]

    by_mes_cat = gastos.groupby(["mes", "categoria"])["abs"].sum().reset_index()
    by_mes_cat.columns = ["Mês", "Categoria", "Total"]

    fig = px.bar(by_mes_cat, x="Mês", y="Total", color="Categoria",
                 barmode="group", color_discrete_sequence=px.colors.qualitative.Set2)
    fig.update_layout(xaxis_title="", yaxis_title="R$", legend_title="Categoria", dragmode=False)
    st.plotly_chart(fig, use_container_width=True, config={"scrollZoom": False, "displayModeBar": False})

    st.subheader("Tabela resumo")
    pivot = by_mes_cat.pivot(index="Categoria", columns="Mês", values="Total").fillna(0)
    st.dataframe(pivot.map(brl), use_container_width=True)

# ── Recorrentes ───────────────────────────────────────────────────────────────
def render_recorrentes(df_all: pd.DataFrame):
    st.subheader("Cobranças recorrentes")
    st.caption("Transações que aparecem em 2 ou mais meses diferentes.")

    gastos = df_all[df_all["valor"] < 0].copy()
    gastos["merchant"] = gastos["descricao"].map(extract_merchant)
    gastos["mes"]      = gastos["data"].dt.to_period("M").astype(str)
    gastos["abs"]      = gastos["valor"].abs()

    por_merchant = gastos.groupby("merchant").agg(
        meses=("mes", "nunique"), media_mensal=("abs", "mean"), total=("abs", "sum"),
    ).reset_index()

    recorrentes = por_merchant[por_merchant["meses"] >= 2].sort_values("total", ascending=False)
    if recorrentes.empty:
        st.info("Nenhuma cobrança recorrente encontrada ainda. Importe mais meses de extrato.")
        return

    recorrentes["media_mensal"] = recorrentes["media_mensal"].map(brl)
    recorrentes["total"]        = recorrentes["total"].map(brl)
    st.dataframe(recorrentes.rename(columns={
        "merchant": "Estabelecimento", "meses": "Meses",
        "media_mensal": "Média mensal", "total": "Total gasto",
    }), hide_index=True, use_container_width=True)

# ── Fragmento de transações (sem scroll ao editar categoria) ──────────────────
@st.fragment
def render_tx_fragment(df_all: pd.DataFrame, periodo_sel: str, cats_excluir: list,
                       usuario: str, user_cats: list):
    mask = df_all["data"].dt.to_period("M").astype(str) == periodo_sel
    view = df_all[mask & ~df_all["categoria"].isin(cats_excluir)].copy()
    view["tipo"] = view["descricao"].map(get_tipo)
    tipo_sel = st.session_state.get("tipo_filter", "Todos")
    if tipo_sel != "Todos":
        view = view[view["tipo"] == tipo_sel]

    st.divider()
    st.subheader("Transações")
    busca = st.text_input("🔍 Buscar", placeholder="ex: uber, ifood, farmácia...")

    tbl = view[["uid", "data", "valor", "descricao", "categoria", "tipo"]].sort_values("data", ascending=False).reset_index(drop=True)
    if busca:
        tbl = tbl[tbl["descricao"].str.contains(busca, case=False, na=False)].reset_index(drop=True)

    uid_index        = tbl["uid"].copy()
    tbl["data"]      = tbl["data"].dt.strftime("%d/%m/%Y")
    tbl["valor"]     = tbl["valor"].map(brl)
    tbl["descricao"] = tbl["descricao"].map(extract_merchant)
    tbl["sel"]       = False
    tbl = tbl.rename(columns={"sel": "✓", "data": "Data", "valor": "Valor",
                               "descricao": "Descrição", "categoria": "Categoria", "tipo": "Tipo"})
    tbl["Categoria ✏️"] = tbl["Categoria"]

    edited = st.data_editor(
        tbl[["✓", "Data", "Valor", "Tipo", "Descrição", "Categoria ✏️"]],
        column_config={
            "✓":          st.column_config.CheckboxColumn("✓", width="small"),
            "Data":       st.column_config.Column(disabled=True),
            "Valor":      st.column_config.Column(disabled=True),
            "Tipo":       st.column_config.Column(disabled=True, width="small"),
            "Descrição":  st.column_config.Column(disabled=True),
            "Categoria ✏️": st.column_config.SelectboxColumn(
                "Categoria ✏️", options=user_cats, required=True,
            ),
        },
        hide_index=True, use_container_width=True, key="tx_editor",
    )

    cat_orig   = tbl["Categoria ✏️"].reset_index(drop=True)
    cat_edited = edited["Categoria ✏️"].reset_index(drop=True)
    pending_cats = {
        uid_index.iloc[i]: cat_edited.iloc[i]
        for i in range(len(cat_edited))
        if cat_edited.iloc[i] != cat_orig.iloc[i]
    }

    selecionados = uid_index[edited[edited["✓"] == True].index].tolist()
    n = len(selecionados)

    if pending_cats:
        ca, cb = st.columns([4, 1])
        if ca.button(f"💾 Salvar {len(pending_cats)} categoria(s) alterada(s)", type="primary", use_container_width=True):
            save_categorias(list(pending_cats.items()), usuario)
            fetch_data.clear()
            st.session_state.pop("tx_editor", None)
            st.rerun(scope="app")
        if cb.button("✕", use_container_width=True, help="Descartar alterações"):
            st.session_state.pop("tx_editor", None)
            st.rerun(scope="app")

    if n > 0:
        st.info(f"**{n} transação(ões) selecionada(s)**")
        a1, a2, a3 = st.columns([3, 1, 1])
        with a1:
            cat_acao = st.selectbox("Definir categoria", user_cats, key="bulk_cat")
        with a2:
            if st.button("✅ Aplicar", use_container_width=True):
                save_categorias([(uid, cat_acao) for uid in selecionados], usuario)
                fetch_data.clear()
                st.session_state.pop("tx_editor", None)
                st.rerun(scope="app")
        with a3:
            if st.button("🚫 Ignorar", use_container_width=True):
                save_categorias([(uid, "Ignorar") for uid in selecionados], usuario)
                fetch_data.clear()
                st.session_state.pop("tx_editor", None)
                st.rerun(scope="app")
    elif not pending_cats:
        st.caption("Clique em **Categoria ✏️** para mudar direto, ou marque ✓ para alterar várias de uma vez.")

    if has_historico(usuario):
        if st.button("↩️ Desfazer última alteração de categorias"):
            n_revert = undo_last_tx(usuario)
            fetch_data.clear()
            st.success(f"{n_revert} transação(ões) revertida(s).")
            st.rerun(scope="app")

    ignoradas = df_all[
        (df_all["data"].dt.to_period("M").astype(str) == periodo_sel) &
        (df_all["categoria"] == "Ignorar")
    ].copy()

    if not ignoradas.empty:
        st.divider()
        with st.expander(f"🙈 Ignoradas neste período ({len(ignoradas)}) — clique para gerenciar"):
            st.caption("Selecione as que quer restaurar e escolha uma categoria, ou restaure uma por vez.")
            ignoradas_tbl = ignoradas.sort_values("data", ascending=False).reset_index(drop=True)
            ign_uid_index = ignoradas_tbl["uid"].copy()
            ignoradas_tbl["✓"]         = False
            ignoradas_tbl["Data"]      = ignoradas_tbl["data"].dt.strftime("%d/%m/%Y")
            ignoradas_tbl["Valor"]     = ignoradas_tbl["valor"].map(brl)
            ignoradas_tbl["Descrição"] = ignoradas_tbl["descricao"].map(extract_merchant)
            ignoradas_tbl["Mover para ✏️"] = "Ignorar"
            ign_cat_orig = ignoradas_tbl["Mover para ✏️"].reset_index(drop=True)

            ign_edited = st.data_editor(
                ignoradas_tbl[["✓", "Data", "Valor", "Descrição", "Mover para ✏️"]],
                column_config={
                    "✓":             st.column_config.CheckboxColumn("✓", width="small"),
                    "Data":          st.column_config.Column(disabled=True),
                    "Valor":         st.column_config.Column(disabled=True),
                    "Descrição":     st.column_config.Column(disabled=True),
                    "Mover para ✏️": st.column_config.SelectboxColumn(
                        "Mover para ✏️", options=user_cats, required=True,
                    ),
                },
                hide_index=True, use_container_width=True, key="ign_editor",
            )

            ign_cat_edited = ign_edited["Mover para ✏️"].reset_index(drop=True)
            ign_pending = {
                ign_uid_index.iloc[i]: ign_cat_edited.iloc[i]
                for i in range(len(ign_cat_edited))
                if ign_cat_edited.iloc[i] != ign_cat_orig.iloc[i]
            }
            if ign_pending:
                if st.button(f"💾 Mover {len(ign_pending)} transação(ões)", type="primary", use_container_width=True):
                    save_categorias(list(ign_pending.items()), usuario)
                    fetch_data.clear()
                    st.session_state.pop("ign_editor", None)
                    st.rerun(scope="app")

            ign_selecionados = ign_uid_index[ign_edited[ign_edited["✓"] == True].index].tolist()
            if ign_selecionados:
                if st.button(f"🗑️ Remover {len(ign_selecionados)} do Ignorar → Não categorizado",
                             use_container_width=True, key="btn_restaurar_ign"):
                    save_categorias([(uid, "Não categorizado") for uid in ign_selecionados], usuario)
                    fetch_data.clear()
                    st.session_state.pop("ign_editor", None)
                    st.rerun(scope="app")
            else:
                st.caption("Clique na coluna 'Mover para' para escolher a categoria, ou marque ✓ para restaurar várias.")

# ── Previsão ──────────────────────────────────────────────────────────────────
def render_previsao(df_all: pd.DataFrame, user_cats: list):
    _EXCLUIR = {"Entrada", "Resgate RDB", "Fatura Cartão", "Investimento", "Ignorar"}
    _NOMES   = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]

    def fmt_mes(s: str) -> str:
        y, m = s.split("-")
        return f"{_NOMES[int(m)-1]}/{y}"

    if df_all.empty or df_all["data"].dt.to_period("M").nunique() < 3:
        st.info("Importe pelo menos 3 meses de extrato para gerar previsões.")
        return

    gastos = df_all[
        (df_all["valor"] < 0) & (~df_all["categoria"].isin(_EXCLUIR))
    ].copy()
    gastos["abs"] = gastos["valor"].abs()
    gastos["mes"] = gastos["data"].dt.to_period("M").astype(str)

    meses_sorted = sorted(gastos["mes"].unique())
    n_meses = len(meses_sorted)
    mes_idx = {m: i for i, m in enumerate(meses_sorted)}
    proximo = str(pd.Period(meses_sorted[-1], freq="M") + 1)

    by_mc = gastos.groupby(["mes", "categoria"])["abs"].sum().reset_index()

    previsoes = []
    for cat in by_mc["categoria"].unique():
        sub = by_mc[by_mc["categoria"] == cat].sort_values("mes")
        if len(sub) < 2:
            continue
        x = np.array([mes_idx[m] for m in sub["mes"]], dtype=float)
        y = sub["abs"].values.astype(float)
        coef     = np.polyfit(x, y, 1)
        prev_val = float(max(0.0, np.polyval(coef, float(n_meses))))
        media    = float(y.mean())
        std      = float(y.std()) if len(y) > 1 else 0.0
        delta    = coef[0]
        tendencia = "📈" if delta > media * 0.05 else ("📉" if delta < -media * 0.05 else "➡️")
        previsoes.append({
            "Categoria": cat, "Tendência": tendencia,
            "Média histórica": media, "Previsão": prev_val,
            "_ic": std,
        })

    if not previsoes:
        st.info("Dados insuficientes para previsão.")
        return

    df_p = pd.DataFrame(previsoes).sort_values("Previsão", ascending=False)

    st.markdown(f"### Projeção para **{fmt_mes(proximo)}**")
    st.caption("Regressão linear sobre o histórico mensal de cada categoria. ★ = ponto previsto.")

    total_prev  = df_p["Previsão"].sum()
    total_media = df_p["Média histórica"].sum()
    diff        = total_prev - total_media
    c1, c2, c3  = st.columns(3)
    c1.metric("Total previsto",    brl(total_prev))
    c2.metric("Média histórica",   brl(total_media))
    c3.metric("Variação",          brl(diff),
              delta=f"{diff/total_media*100:+.1f}%" if total_media > 0 else None,
              delta_color="inverse")
    st.divider()

    # Gráfico barras horizontais com intervalo de confiança
    df_chart = df_p.sort_values("Previsão")
    fig = px.bar(
        df_chart, x="Previsão", y="Categoria", orientation="h",
        error_x=df_chart["_ic"],
        color="Previsão", color_continuous_scale="Purples",
        labels={"Previsão": "R$"},
    )
    fig.update_layout(
        xaxis_title="R$", yaxis_title="",
        coloraxis_showscale=False,
        margin=dict(t=10, b=0), dragmode=False,
    )
    st.plotly_chart(fig, use_container_width=True,
                    config={"scrollZoom": False, "displayModeBar": False})
    st.divider()

    # Tabela resumo
    df_tbl = df_p[["Tendência", "Categoria", "Média histórica", "Previsão"]].copy()
    df_tbl["Média histórica"] = df_tbl["Média histórica"].map(brl)
    df_tbl["Previsão"]        = df_tbl["Previsão"].map(brl)
    st.dataframe(df_tbl, hide_index=True, use_container_width=True)
    st.divider()

    # Linha histórica + ponto previsto
    st.subheader("Evolução histórica por categoria")
    cats_disp = list(by_mc["categoria"].unique())
    cats_sel  = st.multiselect("Categorias", cats_disp,
                               default=cats_disp[:min(5, len(cats_disp))],
                               key="prev_cats")
    if cats_sel:
        hist = by_mc[by_mc["categoria"].isin(cats_sel)].copy()
        hist["mes_fmt"] = hist["mes"].apply(fmt_mes)

        # Adiciona ponto de previsão
        extras = []
        for cat in cats_sel:
            row = df_p[df_p["Categoria"] == cat]
            if not row.empty:
                extras.append({"mes": proximo,
                               "mes_fmt": fmt_mes(proximo) + " ★",
                               "categoria": cat,
                               "abs": row.iloc[0]["Previsão"]})
        if extras:
            hist = pd.concat([hist, pd.DataFrame(extras)], ignore_index=True)

        fig2 = px.line(hist, x="mes_fmt", y="abs", color="categoria",
                       markers=True,
                       color_discrete_sequence=px.colors.qualitative.Set2,
                       labels={"mes_fmt": "Mês", "abs": "R$", "categoria": "Categoria"})
        fig2.update_layout(xaxis_title="", yaxis_title="R$", dragmode=False)
        st.plotly_chart(fig2, use_container_width=True,
                        config={"scrollZoom": False, "displayModeBar": False})

# ── Relatório / Exportação ─────────────────────────────────────────────────────
def _gerar_pdf(df_all: pd.DataFrame, mes: str, usuario: str,
               orcamentos: dict, rendas_df: pd.DataFrame) -> bytes:
    from fpdf import FPDF

    _NOMES   = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]
    _EXCLUIR = {"Fatura Cartão", "Investimento", "Resgate RDB", "Ignorar"}
    ROXO  = (88, 28, 135)
    ROXO_L= (245, 240, 255)
    CINZA = (100, 100, 100)
    VERDE = (22, 163, 74)
    VERM  = (220, 38, 38)
    AMAR  = (180, 120, 0)
    BCO   = (255, 255, 255)
    PRETO = (30, 30, 30)

    def fmt_mes(s):
        y, m = s.split("-")
        return f"{_NOMES[int(m)-1]}/{y}"

    def p(text, n=100):
        return str(text)[:n].encode("latin-1", errors="replace").decode("latin-1")

    # ── Dados principais ──────────────────────────────────────────────────────
    mask    = df_all["data"].dt.to_period("M").astype(str) == mes
    df_mes  = df_all[mask].copy()
    df_view = df_mes[~df_mes["categoria"].isin(_EXCLUIR)].copy()
    entradas    = float(df_view[df_view["valor"] > 0]["valor"].sum())
    saidas      = float(df_view[df_view["valor"] < 0]["valor"].sum())
    saldo       = entradas + saidas
    total_renda = float(rendas_df["Valor (R$)"].sum()) if not rendas_df.empty else 0.0

    df_g = df_view[df_view["valor"] < 0].copy()
    df_g["abs"] = df_g["valor"].abs()
    by_cat       = df_g.groupby("categoria")["abs"].sum().reset_index().sort_values("abs", ascending=False)
    total_gastos = float(by_cat["abs"].sum())

    # ── Mês anterior ──────────────────────────────────────────────────────────
    mes_ant  = str(pd.Period(mes, freq="M") - 1)
    df_ant_g = df_all[
        (df_all["data"].dt.to_period("M").astype(str) == mes_ant) &
        (~df_all["categoria"].isin(_EXCLUIR)) & (df_all["valor"] < 0)
    ].copy()
    df_ant_g["abs"] = df_ant_g["valor"].abs()
    by_cat_ant = df_ant_g.groupby("categoria")["abs"].sum().to_dict() if not df_ant_g.empty else {}

    # ── Média histórica ────────────────────────────────────────────────────────
    media_hist = {}
    if df_all["data"].dt.to_period("M").nunique() >= 2:
        media_hist = (
            df_all[(df_all["valor"] < 0) & (~df_all["categoria"].isin(_EXCLUIR))]
            .assign(abs=lambda d: d["valor"].abs(),
                    mes_h=lambda d: d["data"].dt.to_period("M").astype(str))
            .groupby(["mes_h","categoria"])["abs"].sum()
            .groupby("categoria").mean().to_dict()
        )

    # ── Estabelecimentos e semanal ─────────────────────────────────────────────
    df_g["merchant"] = df_g["descricao"].apply(extract_merchant)
    top_merch = (df_g.groupby("merchant")
                 .agg(total=("abs","sum"), qtd=("abs","count"))
                 .reset_index().sort_values("total", ascending=False).head(10))
    df_g["semana"] = df_g["data"].apply(lambda d: f"Semana {(d.day-1)//7 + 1}")
    por_semana = df_g.groupby("semana")["abs"].sum().reset_index().sort_values("semana")

    # ── Classe PDF com rodapé ──────────────────────────────────────────────────
    class PDF(FPDF):
        def footer(self):
            self.set_y(-11)
            self.set_draw_color(*CINZA)
            self.set_line_width(0.2)
            self.line(15, self.get_y(), 195, self.get_y())
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(*CINZA)
            txt = p(f"Controle Financeiro  |  {fmt_mes(mes)}  |  {usuario}  |  Pag. {self.page_no()}")
            self.cell(0, 6, txt, align="C")

    pdf = PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(15, 15, 15)
    W = 180

    # ── Helpers de layout ─────────────────────────────────────────────────────
    def section(title):
        if pdf.get_y() > 248:
            pdf.add_page()
        else:
            pdf.ln(4)
        pdf.set_draw_color(*ROXO)
        pdf.set_line_width(0.3)
        pdf.set_fill_color(*ROXO_L)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*ROXO)
        pdf.cell(W, 7, p(f"  {title}"), border="LB", fill=True, ln=True)
        pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.2)
        pdf.ln(1)

    def th(*cols):
        pdf.set_fill_color(*ROXO_L)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.2)
        for w, lbl, aln in cols:
            pdf.cell(w, 6, p(lbl), border=1, fill=True, align=aln)
        pdf.ln()

    def tr(*cols_vals, fill=False):
        if fill:
            pdf.set_fill_color(250, 248, 255)
        else:
            pdf.set_fill_color(*BCO)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.2)
        for w, val, aln in cols_vals:
            pdf.cell(w, 5.5, p(str(val), int(w * 2.5)), border=1, fill=True, align=aln)
        pdf.ln()

    def tr_total(*cols_vals):
        pdf.set_fill_color(*ROXO_L)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180, 180, 180)
        for w, val, aln in cols_vals:
            pdf.cell(w, 6, p(str(val), int(w * 2.5)), border=1, fill=True, align=aln)
        pdf.ln()

    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()

    # ── Banner roxo ───────────────────────────────────────────────────────────
    pdf.set_fill_color(*ROXO)
    pdf.rect(0, 0, 210, 30, style="F")
    pdf.set_xy(15, 5)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*BCO)
    pdf.cell(W, 10, "Controle Financeiro", align="C", ln=True)
    pdf.set_xy(15, 16)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(W, 7, p(f"Relatorio Mensal  -  {fmt_mes(mes)}"), align="C", ln=True)
    pdf.set_xy(15, 24)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(W, 5, p(f"Gerado em {datetime.now().strftime('%d/%m/%Y as %H:%M')}  |  Usuario: {usuario}"), align="C")
    pdf.set_y(35)

    # ── Resumo Financeiro (caixas) ────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*ROXO)
    pdf.set_fill_color(*ROXO_L)
    pdf.cell(W, 7, "  Resumo Financeiro", border="LB", fill=True, ln=True)
    pdf.set_draw_color(180, 180, 180); pdf.set_line_width(0.2); pdf.ln(2)

    bw = W / 3
    labels_m = ["Entradas", "Saidas", "Saldo"]
    values_m = [brl(entradas), brl(abs(saidas)), brl(saldo)]
    colors_m = [VERDE, VERM, VERDE if saldo >= 0 else VERM]
    yb = pdf.get_y()
    for i, (lbl, val, col) in enumerate(zip(labels_m, values_m, colors_m)):
        x = 15 + i * bw
        pdf.set_fill_color(250, 248, 255)
        pdf.rect(x, yb, bw - 1, 17, style="FD")
        pdf.set_xy(x, yb + 1.5)
        pdf.set_font("Helvetica", "", 8); pdf.set_text_color(*CINZA)
        pdf.cell(bw - 1, 5, lbl, align="C")
        pdf.set_xy(x, yb + 7)
        pdf.set_font("Helvetica", "B", 12); pdf.set_text_color(*col)
        pdf.cell(bw - 1, 8, p(val), align="C")
    pdf.set_y(yb + 20)

    if total_renda > 0:
        pct_r = abs(saidas) / total_renda * 100
        col_r = VERDE if pct_r <= 80 else (AMAR if pct_r <= 100 else VERM)
        pdf.set_font("Helvetica", "", 9); pdf.set_text_color(*col_r)
        pdf.cell(W, 5, p(f"Comprometimento da renda: {pct_r:.1f}%   ({brl(abs(saidas))} de {brl(total_renda)})"), align="C", ln=True)
    pdf.ln(2)

    # ── Fontes de Renda ───────────────────────────────────────────────────────
    if not rendas_df.empty and total_renda > 0:
        section("Fontes de Renda")
        th((130,"Fonte","L"),(50,"Valor","R"))
        for i, (_, row) in enumerate(rendas_df.iterrows()):
            pct_ri = float(row["Valor (R$)"]) / total_renda * 100 if total_renda > 0 else 0
            tr((130, f"{row['Fonte de renda']}  ({pct_ri:.1f}%)", "L"),
               (50, brl(float(row["Valor (R$)"])), "R"), fill=bool(i % 2))
        tr_total((130,"TOTAL","L"),(50, brl(total_renda),"R"))

    # ── Gastos por Categoria ──────────────────────────────────────────────────
    section("Gastos por Categoria")
    th((72,"Categoria","L"),(32,"Total","R"),(20,"%","R"),(30,"Acum.%","R"),(26,"vs Media","R"))
    acum = 0.0
    for i, (_, row) in enumerate(by_cat.iterrows()):
        pct_f = row["abs"] / total_gastos * 100 if total_gastos > 0 else 0
        acum += pct_f
        med   = media_hist.get(row["categoria"])
        if med and med > 0:
            vm_s = f"{(row['abs']/med - 1)*100:+.0f}%"
            vm_c = VERM if row["abs"] > med * 1.1 else (AMAR if row["abs"] > med * 0.9 else VERDE)
        else:
            vm_s, vm_c = "-", CINZA
        if i % 2:
            pdf.set_fill_color(250, 248, 255)
        else:
            pdf.set_fill_color(*BCO)
        pdf.set_font("Helvetica","",8); pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
        pdf.cell(72, 5.5, p(row["categoria"],36), border=1, fill=True)
        pdf.cell(32, 5.5, p(brl(row["abs"])), border=1, fill=True, align="R")
        pdf.cell(20, 5.5, f"{pct_f:.1f}%", border=1, fill=True, align="R")
        pdf.cell(30, 5.5, f"{acum:.1f}%", border=1, fill=True, align="R")
        pdf.set_text_color(*vm_c)
        pdf.cell(26, 5.5, vm_s, border=1, fill=True, align="R")
        pdf.ln()
    tr_total((72,"TOTAL","L"),(32,brl(total_gastos),"R"),(20,"100%","R"),(30,"","L"),(26,"","L"))

    # ── Orçamento vs Realizado ────────────────────────────────────────────────
    if orcamentos:
        section("Orcamento vs Realizado")
        th((60,"Categoria","L"),(28,"Orcado","R"),(28,"Realizado","R"),(28,"Diferenca","R"),(20,"Uso %","R"),(16,"","C"))
        tot_o = 0.0; tot_r = 0.0
        for i, cat in enumerate(sorted(orcamentos.keys())):
            lim  = float(orcamentos[cat])
            real = float(by_cat[by_cat["categoria"]==cat]["abs"].sum()) if cat in by_cat["categoria"].values else 0.0
            diff = lim - real
            uso  = real / lim * 100 if lim > 0 else 0
            tot_o += lim; tot_r += real
            if i % 2:
                pdf.set_fill_color(250, 248, 255)
            else:
                pdf.set_fill_color(*BCO)
            pdf.set_font("Helvetica","",8); pdf.set_text_color(*PRETO)
            pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
            pdf.cell(60, 5.5, p(cat,30), border=1, fill=True)
            pdf.cell(28, 5.5, p(brl(lim)), border=1, fill=True, align="R")
            pdf.cell(28, 5.5, p(brl(real)), border=1, fill=True, align="R")
            pdf.set_text_color(*VERM if diff < 0 else VERDE)
            pdf.cell(28, 5.5, p(brl(diff)), border=1, fill=True, align="R")
            pdf.set_text_color(*VERM if uso > 100 else (AMAR if uso > 85 else VERDE))
            pdf.cell(20, 5.5, f"{uso:.0f}%", border=1, fill=True, align="R")
            pdf.set_text_color(*PRETO)
            if real <= lim:
                pdf.set_fill_color(220,255,220)
            else:
                pdf.set_fill_color(255,220,220)
            pdf.cell(16, 5.5, "OK" if real <= lim else "!", border=1, fill=True, align="C")
            pdf.ln()
        uso_tot = tot_r / tot_o * 100 if tot_o > 0 else 0
        tr_total((60,"TOTAL","L"),(28,brl(tot_o),"R"),(28,brl(tot_r),"R"),
                 (28,brl(tot_o-tot_r),"R"),(20,f"{uso_tot:.0f}%","R"),(16,"","C"))

    # ── Comparativo com Mês Anterior ──────────────────────────────────────────
    if by_cat_ant:
        section(f"Comparativo: {fmt_mes(mes_ant)}  vs  {fmt_mes(mes)}")
        th((70,"Categoria","L"),(28,fmt_mes(mes_ant),"R"),(28,fmt_mes(mes),"R"),(27,"Var. R$","R"),(27,"Var. %","R"))
        cats_c = sorted(set(list(by_cat["categoria"].values) + list(by_cat_ant.keys())))
        for i, cat in enumerate(cats_c):
            ant   = by_cat_ant.get(cat, 0.0)
            atual = float(by_cat[by_cat["categoria"]==cat]["abs"].sum()) if cat in by_cat["categoria"].values else 0.0
            delta = atual - ant
            pct_d = (delta / ant * 100) if ant > 0 else (100.0 if atual > 0 else 0.0)
            if i % 2:
                pdf.set_fill_color(250, 248, 255)
            else:
                pdf.set_fill_color(*BCO)
            pdf.set_font("Helvetica","",8); pdf.set_text_color(*PRETO)
            pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
            pdf.cell(70, 5.5, p(cat,35), border=1, fill=True)
            pdf.cell(28, 5.5, p(brl(ant)), border=1, fill=True, align="R")
            pdf.cell(28, 5.5, p(brl(atual)), border=1, fill=True, align="R")
            d_col = VERM if delta > 0 else VERDE
            pdf.set_text_color(*d_col)
            sign = "+" if delta >= 0 else ""
            pdf.cell(27, 5.5, p(f"{sign}{brl(delta)}"), border=1, fill=True, align="R")
            pdf.cell(27, 5.5, p(f"{sign}{pct_d:.1f}%"), border=1, fill=True, align="R")
            pdf.ln()

    # ── Alertas ────────────────────────────────────────────────────────────────
    if media_hist:
        alertas = [(c, float(v), media_hist[c])
                   for c, v in by_cat.set_index("categoria")["abs"].items()
                   if c in media_hist and float(v) > media_hist[c] * 1.2]
        if alertas:
            section("Alertas - Categorias Acima da Media Historica (>20%)")
            th((65,"Categoria","L"),(38,"Este mes","R"),(37,"Media hist.","R"),(40,"Excesso","R"))
            for i, (cat, atual, med) in enumerate(sorted(alertas, key=lambda x: x[1]-x[2], reverse=True)):
                if i % 2:
                    pdf.set_fill_color(255,245,245)
                else:
                    pdf.set_fill_color(255,252,252)
                pdf.set_font("Helvetica","",8); pdf.set_text_color(*PRETO)
                pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
                pdf.cell(65, 5.5, p(cat,32), border=1, fill=True)
                pdf.cell(38, 5.5, p(brl(atual)), border=1, fill=True, align="R")
                pdf.cell(37, 5.5, p(brl(med)), border=1, fill=True, align="R")
                pdf.set_text_color(*VERM)
                pdf.cell(40, 5.5, p(f"+{brl(atual - med)}"), border=1, fill=True, align="R")
                pdf.ln()

    # ── Top 10 Estabelecimentos ────────────────────────────────────────────────
    if not top_merch.empty:
        section("Top 10 Estabelecimentos")
        th((80,"Estabelecimento","L"),(20,"Qtd","C"),(40,"Total","R"),(40,"% dos gastos","R"))
        for i, (_, row) in enumerate(top_merch.iterrows()):
            pct_m = row["total"] / total_gastos * 100 if total_gastos > 0 else 0
            tr((80,row["merchant"],"L"),(20,int(row["qtd"]),"C"),
               (40,brl(row["total"]),"R"),(40,f"{pct_m:.1f}%","R"), fill=bool(i%2))

    # ── Distribuição Semanal ──────────────────────────────────────────────────
    if not por_semana.empty:
        section("Distribuicao Semanal de Gastos")
        th((60,"Semana","L"),(60,"Total","R"),(60,"% do mes","R"))
        for i, (_, row) in enumerate(por_semana.iterrows()):
            pct_s = row["abs"] / total_gastos * 100 if total_gastos > 0 else 0
            tr((60,row["semana"],"L"),(60,brl(row["abs"]),"R"),(60,f"{pct_s:.1f}%","R"), fill=bool(i%2))

    # ── Top 10 Maiores Gastos ──────────────────────────────────────────────────
    top10 = df_g.nlargest(10,"abs")[["data","descricao","categoria","abs"]].copy()
    if not top10.empty:
        section("Top 10 Maiores Gastos do Mes")
        th((25,"Data","L"),(73,"Descricao","L"),(50,"Categoria","L"),(32,"Valor","R"))
        for i, (_, row) in enumerate(top10.iterrows()):
            tr((25,row["data"].strftime("%d/%m/%Y"),"L"),
               (73,extract_merchant(row["descricao"]),"L"),
               (50,row["categoria"],"L"),(32,brl(row["abs"]),"R"), fill=bool(i%2))

    # ── Histórico Mensal de Saídas ────────────────────────────────────────────
    if df_all["data"].dt.to_period("M").nunique() >= 2:
        hist = (df_all[(df_all["valor"] < 0) & (~df_all["categoria"].isin(_EXCLUIR))]
                .assign(abs=lambda d: d["valor"].abs(),
                        mes_h=lambda d: d["data"].dt.to_period("M").astype(str))
                .groupby("mes_h")["abs"].sum().reset_index().sort_values("mes_h"))
        hist["fmt"] = hist["mes_h"].apply(fmt_mes)
        section("Historico Mensal de Saidas")
        n_h = len(hist)
        cw_h = min(35, W // n_h)
        pdf.set_fill_color(*ROXO_L); pdf.set_font("Helvetica","B",8); pdf.set_text_color(*PRETO)
        pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
        for _, row in hist.iterrows():
            pdf.cell(cw_h, 6, p(row["fmt"]), border=1, fill=True, align="C")
        pdf.ln()
        pdf.set_fill_color(*BCO); pdf.set_font("Helvetica","",8)
        for _, row in hist.iterrows():
            pdf.cell(cw_h, 5.5, p(brl(row["abs"])), border=1, fill=True, align="C")
        pdf.ln()

    # ── Extrato Completo ───────────────────────────────────────────────────────
    section("Extrato Completo do Mes")
    pdf.set_font("Helvetica","I",7); pdf.set_text_color(*CINZA)
    pdf.cell(W, 4, p(f"  {len(df_mes)} transacoes no periodo"), ln=True)
    pdf.ln(1)
    th((22,"Data","L"),(78,"Descricao","L"),(42,"Categoria","L"),(38,"Valor","R"))
    for i, (_, row) in enumerate(df_mes.sort_values("data").iterrows()):
        val = float(row["valor"])
        if i % 2:
            pdf.set_fill_color(250,248,255)
        else:
            pdf.set_fill_color(*BCO)
        pdf.set_font("Helvetica","",7)
        pdf.set_draw_color(180,180,180); pdf.set_line_width(0.2)
        pdf.set_text_color(*PRETO)
        pdf.cell(22, 5, row["data"].strftime("%d/%m/%Y"), border=1, fill=True)
        pdf.cell(78, 5, p(extract_merchant(row["descricao"]),42), border=1, fill=True)
        pdf.cell(42, 5, p(row["categoria"],22), border=1, fill=True)
        pdf.set_text_color(*VERM if val < 0 else VERDE)
        pdf.cell(38, 5, p(brl(val)), border=1, fill=True, align="R")
        pdf.ln()

    return bytes(pdf.output())


def render_relatorio(df_all: pd.DataFrame, usuario: str):
    _NOMES   = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]
    _EXCLUIR = {"Fatura Cartão", "Investimento", "Resgate RDB", "Ignorar"}

    def fmt_mes(s):
        y, m = s.split("-")
        return f"{_NOMES[int(m)-1]}/{y}"

    st.subheader("Relatório financeiro")
    if df_all.empty:
        st.info("Importe um extrato para gerar relatórios.")
        return

    meses     = sorted(df_all["data"].dt.to_period("M").astype(str).unique(), reverse=True)
    col_ms, _ = st.columns([2, 4])
    mes_sel   = col_ms.selectbox("📅 Mês", meses, format_func=fmt_mes, key="mes_relatorio")

    orcamentos = fetch_orcamentos(mes_sel, usuario)
    rendas_df  = fetch_rendas(usuario, mes_sel)
    pdf_bytes  = _gerar_pdf(df_all, mes_sel, usuario, orcamentos, rendas_df)
    st.download_button(
        label="⬇️ Baixar PDF",
        data=pdf_bytes,
        file_name=f"relatorio_{mes_sel}_{usuario}.pdf",
        mime="application/pdf",
        use_container_width=True,
        type="primary",
    )
    st.caption("O PDF contém: resumo, rendas, gastos por categoria, orçamento vs realizado, comparativo com mês anterior, alertas, top estabelecimentos, distribuição semanal, top 10 gastos e extrato completo.")
    st.divider()

    st.subheader("Prévia")
    mask     = df_all["data"].dt.to_period("M").astype(str) == mes_sel
    df_mes   = df_all[mask].copy()
    df_view  = df_mes[~df_mes["categoria"].isin(_EXCLUIR)].copy()
    entradas = float(df_view[df_view["valor"] > 0]["valor"].sum())
    saidas   = float(df_view[df_view["valor"] < 0]["valor"].sum())
    c1, c2, c3 = st.columns(3)
    c1.metric("💰 Entradas", brl(entradas))
    c2.metric("💸 Saídas",   brl(abs(saidas)))
    c3.metric("📊 Saldo",    brl(entradas + saidas))
    st.divider()
    df_gastos = df_view[df_view["valor"] < 0].copy()
    df_gastos["abs"] = df_gastos["valor"].abs()
    by_cat = (df_gastos.groupby("categoria")["abs"].sum()
              .reset_index().sort_values("abs", ascending=False))
    total_s = float(by_cat["abs"].sum())
    by_cat["% do total"] = (by_cat["abs"] / total_s * 100).map(lambda v: f"{v:.1f}%") if total_s > 0 else "—"
    by_cat["abs"] = by_cat["abs"].map(brl)
    by_cat = by_cat.rename(columns={"categoria": "Categoria", "abs": "Total"})
    st.dataframe(by_cat, hide_index=True, use_container_width=True)

# ── Regras ────────────────────────────────────────────────────────────────────
def render_regras(rules: dict, usuario: str, user_cats: list):
    st.subheader("Regras de categorização")
    st.caption("Palavras-chave usadas para categorizar automaticamente ao importar.")

    if has_rules_backup(usuario):
        if st.button("↩️ Desfazer última exclusão de categoria"):
            had_tx = undo_last_tx(usuario)
            undo_rules(usuario)
            fetch_data.clear()
            msg = "Categoria restaurada."
            if had_tx:
                msg += f" {had_tx} transação(ões) revertida(s)."
            st.success(msg)
            st.rerun()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Categorias existentes**")
        for cat, kws in list(rules.items()):
            with st.expander(f"{cat}  —  {len(kws)} palavra(s)-chave"):
                if kws:
                    for kw in kws:
                        c1, c2_btn = st.columns([5, 1])
                        c1.markdown(f"`{kw}`")
                        if c2_btn.button("✕", key=f"del_{cat}_{kw}", help=f"Remover '{kw}'"):
                            rules[cat].remove(kw)
                            save_rules(rules, usuario)
                            st.rerun()
                else:
                    st.caption("*(sem palavras-chave)*")

                nova = st.text_input("Adicionar palavra-chave", key=f"add_{cat}", placeholder="ex: padaria")
                ca, cb = st.columns(2)
                if ca.button("Adicionar", key=f"btn_{cat}") and nova:
                    if nova.lower() not in [k.lower() for k in kws]:
                        rules[cat].append(nova.lower())
                        save_rules(rules, usuario)
                        st.rerun()
                if cb.button("🗑️ Excluir categoria", key=f"delcat_{cat}", type="primary"):
                    n_tx = delete_categoria_completa(cat, rules, usuario)
                    fetch_data.clear()
                    msg = f"Categoria '{cat}' excluída."
                    if n_tx:
                        msg += f" {n_tx} transação(ões) movida(s) para 'Não categorizado'."
                    st.success(msg)
                    st.rerun()

    with col2:
        st.markdown("**Criar nova categoria**")
        nova_cat = st.text_input("Nome da categoria", placeholder="ex: Lazer")
        nova_kw  = st.text_input("Palavra-chave inicial (opcional)", placeholder="ex: cinema")
        if st.button("Criar categoria", type="primary") and nova_cat:
            if nova_cat not in rules:
                rules[nova_cat] = [nova_kw.lower()] if nova_kw else []
                save_rules(rules, usuario)
                st.success(f"Categoria '{nova_cat}' criada!")
                st.rerun()
            else:
                st.warning("Categoria já existe.")

# ── Main ──────────────────────────────────────────────────────────────────────
def inject_mobile_css():
    st.markdown("""
    <style>
    @media screen and (max-width: 640px) {
        /* Empilha colunas verticalmente no celular */
        div[data-testid="stHorizontalBlock"] {
            flex-direction: column !important;
        }
        div[data-testid="column"] {
            min-width: 100% !important;
            flex: none !important;
        }
        /* Evita zoom automático em inputs no iOS */
        input, textarea, select {
            font-size: 16px !important;
        }
        /* Botões maiores para toque */
        div[data-testid="stButton"] button {
            width: 100% !important;
            min-height: 2.75rem !important;
        }
        /* Tabelas com scroll horizontal */
        div[data-testid="stDataEditorContainer"],
        div[data-testid="stDataFrameContainer"] {
            overflow-x: auto !important;
        }
        /* Tabs com scroll horizontal quando necessário */
        div[data-testid="stTabs"] > div:first-child {
            overflow-x: auto !important;
            white-space: nowrap !important;
        }
        /* Menos padding nas bordas */
        .main .block-container {
            padding-left: 0.75rem !important;
            padding-right: 0.75rem !important;
        }
        /* Radio buttons quebram linha se necessário */
        div[data-testid="stRadio"] > div {
            flex-wrap: wrap !important;
            gap: 0.25rem !important;
        }
        /* Gráficos ocupam largura total */
        div[data-testid="stPlotlyChart"] {
            width: 100% !important;
        }
        /* Métricas sem truncar */
        [data-testid="stMetricValue"] {
            font-size: 1.1rem !important;
            white-space: normal !important;
            overflow: visible !important;
            word-break: break-word !important;
        }
        /* Seta do selectbox no ag-grid sempre visível */
        .ag-cell .ag-cell-editor .ag-picker-field-wrapper,
        .ag-cell-editor-popup .ag-picker-field-wrapper {
            display: flex !important;
        }
        .ag-select .ag-picker-field-icon {
            opacity: 1 !important;
        }
        /* Área de toque maior para células editáveis */
        .ag-cell[col-id="Categoria ✏️"],
        .ag-cell[col-id="Mover para ✏️"] {
            cursor: pointer !important;
            -webkit-tap-highlight-color: rgba(139,92,246,0.2) !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

def main():
    db_init()
    _migrar_rendas()
    _migrar_auth()
    inject_mobile_css()

    # Fix de teclado no ag-grid SelectboxColumn no mobile (bug 5)
    import streamlit.components.v1 as components
    components.html("""
    <script>
    (function() {
        function fixInputMode() {
            try {
                var doc = window.parent ? window.parent.document : document;
                doc.querySelectorAll('.ag-text-field-input').forEach(function(el) {
                    if (!el.getAttribute('inputmode-fixed')) {
                        el.setAttribute('inputmode', 'none');
                        el.setAttribute('inputmode-fixed', '1');
                    }
                });
            } catch(e) {}
        }
        setInterval(fixInputMode, 400);
        fixInputMode();
    })();
    </script>
    """, height=0, scrolling=False)

    if "usuario" not in st.session_state:
        render_login()
        return

    usuario = st.session_state["usuario"]

    if "_ultimo_acesso" in st.session_state:
        ult = st.session_state.pop("_ultimo_acesso")
        st.toast(f"Último acesso: {ult}", icon="🕐")

    # Carregar regras e categorias ANTES da sidebar para que checkboxes incluam cats customizadas
    rules = load_rules(usuario)
    user_cats = list(ALL_CATS)
    for cat in rules:
        if cat not in user_cats:
            user_cats.append(cat)

    _EXCLUIR_DEFAULTS = {
        "Fatura Cartão": True, "Investimento": True, "Resgate RDB": True, "Ignorar": True,
        "Entrada": False, "Pix Recebido": False, "Pix Enviado": False,
        "Transporte": False, "Alimentação": False, "Saúde": False,
        "Telefone/Internet": False, "Dívidas/Boletos": False, "Outros": False,
    }

    with st.sidebar:
        st.title("💜 Controle Financeiro")
        col_u, col_s = st.columns([3, 1])
        col_u.caption(f"👤 {usuario}")
        if col_s.button("Sair"):
            del st.session_state["usuario"]
            st.rerun()

        file = st.file_uploader("Importar extrato", type=["csv", "ofx", "qfx", "txt"])
        if file:
            rows, banco = parse_file(file, rules)
            if not rows:
                st.error(f"Não foi possível ler o arquivo. Formato não reconhecido.")
            else:
                n = import_rows(rows, usuario)
                fetch_data.clear()
                if n:
                    st.success(f"✅ {n} transações importadas! ({banco})")
                    st.rerun()
                else:
                    st.info(f"Nenhuma transação nova. ({banco})")

        st.divider()
        df_all = fetch_data(usuario)

        if df_all.empty:
            st.info("Importe um extrato CSV para começar.")
            st.stop()

        _nomes = ["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"]
        periodos     = sorted(df_all["data"].dt.to_period("M").unique(), reverse=True)
        periodos_str = [str(p) for p in periodos]
        periodo_sel  = st.selectbox(
            "Período", periodos_str,
            format_func=lambda s: f"{_nomes[int(s.split('-')[1])-1]}/{s.split('-')[0]}"
        )

        st.markdown("**Excluir dos totais**")
        # Inclui todas as categorias (inclusive as customizadas criadas pelo usuário)
        sidebar_cats = list(_EXCLUIR_DEFAULTS.keys())
        for cat in user_cats:
            if cat not in sidebar_cats and cat != "Não categorizado":
                sidebar_cats.append(cat)

        cats_excluir = []
        c1, c2 = st.columns(2)
        for i, cat in enumerate(sidebar_cats):
            col = c1 if i % 2 == 0 else c2
            default = _EXCLUIR_DEFAULTS.get(cat, False)
            if col.checkbox(cat, value=default, key=f"excl_{cat}"):
                cats_excluir.append(cat)

        st.divider()
        with st.expander("⚠️ Zona de perigo"):
            st.caption("Apaga todo o histórico do banco de dados.")
            confirmar = st.checkbox("Confirmar exclusão")
            if st.button("Apagar todos os dados", type="primary", disabled=not confirmar):
                delete_all_data(usuario)
                fetch_data.clear()
                fetch_orcamentos.clear()
                fetch_rendas.clear()
                st.rerun()

    t1, t2, t3, t4, t5, t6, t7 = st.tabs([
        "📊 Dashboard", "💰 Orçamento", "📉 Previsão",
        "📈 Histórico", "🔄 Recorrentes", "📄 Relatório", "⚙️ Regras"
    ])
    with t1: render_dashboard(df_all, periodo_sel, cats_excluir, usuario, user_cats)
    with t2: render_orcamento(df_all, usuario, user_cats)
    with t3: render_previsao(df_all, user_cats)
    with t4: render_historico(df_all, user_cats)
    with t5: render_recorrentes(df_all)
    with t6: render_relatorio(df_all, usuario)
    with t7: render_regras(rules, usuario, user_cats)


if __name__ == "__main__":
    main()
