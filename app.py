import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
import hashlib
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text

st.set_page_config(page_title="Nubank Tracker", page_icon="💜", layout="wide")

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
                nome TEXT, usuario TEXT, valor REAL,
                PRIMARY KEY (nome, usuario)
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

# ── Auth ──────────────────────────────────────────────────────────────────────
def hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()

def user_exists(nome: str) -> bool:
    rows, _ = db_exec("SELECT 1 FROM usuarios WHERE nome=:n", {"n": nome}, fetch=True)
    return bool(rows)

def verify_pin(nome: str, pin: str) -> bool:
    rows, _ = db_exec(
        "SELECT 1 FROM usuarios WHERE nome=:n AND pin_hash=:h",
        {"n": nome, "h": hash_pin(pin)}, fetch=True
    )
    return bool(rows)

def create_user(nome: str, pin: str):
    db_exec(
        "INSERT INTO usuarios (nome, pin_hash) VALUES (:n, :h) ON CONFLICT (nome) DO NOTHING",
        {"n": nome, "h": hash_pin(pin)}
    )

# ── Rules per user ────────────────────────────────────────────────────────────
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

def backup_rules(rules: dict, usuario: str):
    db_exec("""
        INSERT INTO preferencias (usuario, chave, valor) VALUES (:u, 'regras_backup', :v)
        ON CONFLICT (usuario, chave) DO UPDATE SET valor=EXCLUDED.valor
    """, {"u": usuario, "v": json.dumps(rules, ensure_ascii=False)})

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
    return True

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
def fetch_rendas(usuario: str) -> pd.DataFrame:
    rows, _ = db_exec(
        "SELECT nome, valor FROM rendas WHERE usuario=:u ORDER BY nome",
        {"u": usuario}, fetch=True
    )
    if rows:
        return pd.DataFrame(rows, columns=["Fonte de renda", "Valor (R$)"])
    return pd.DataFrame([{"Fonte de renda": "Salário", "Valor (R$)": 0.0}])

@st.cache_data
def fetch_orcamentos(mes: str, usuario: str) -> dict:
    rows, _ = db_exec(
        "SELECT categoria, limite FROM orcamentos WHERE mes=:m AND usuario=:u",
        {"m": mes, "u": usuario}, fetch=True
    )
    return {r[0]: float(r[1]) for r in rows} if rows else {}

# ── Write ─────────────────────────────────────────────────────────────────────
def save_rendas(df: pd.DataFrame, usuario: str):
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM rendas WHERE usuario=:u"), {"u": usuario})
        for _, row in df.iterrows():
            nome_val = row["Fonte de renda"]
            if pd.notna(nome_val) and str(nome_val).strip():
                conn.execute(
                    text("INSERT INTO rendas (nome, usuario, valor) VALUES (:n, :u, :v)"),
                    {"n": str(nome_val).strip(), "u": usuario, "v": float(row["Valor (R$)"])}
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

def parse_csv(file, rules: dict) -> list[dict]:
    try:
        df = pd.read_csv(file, encoding="utf-8")
    except UnicodeDecodeError:
        file.seek(0)
        df = pd.read_csv(file, encoding="latin-1")
    df.columns = ["Data", "Valor", "Identificador", "Descrição"]
    df["Valor"] = df["Valor"].astype(float)
    df = df[~df["Descrição"].str.startswith("Valor adicionado", na=False)].copy()
    rows, seen = [], {}
    for _, r in df.iterrows():
        base = r["Identificador"] + ("_p" if r["Valor"] > 0 else "_n")
        seen[base] = seen.get(base, 0) + 1
        uid = f"{base}_{seen[base]}" if seen[base] > 1 else base
        rows.append({
            "uid":       uid,
            "data":      pd.to_datetime(r["Data"], format="%d/%m/%Y").strftime("%Y-%m-%d"),
            "valor":     r["Valor"],
            "descricao": r["Descrição"],
            "categoria": categorize(r["Descrição"], r["Valor"], rules),
        })
    return rows

def brl(v: float) -> str:
    s = f"R$ {abs(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"-{s}" if v < 0 else s

# ── Login ─────────────────────────────────────────────────────────────────────
def render_login():
    _, col, _ = st.columns([1, 1.5, 1])
    with col:
        st.markdown("## 💜 Nubank Tracker")
        st.markdown("---")
        modo = st.radio("", ["Entrar", "Criar conta"], horizontal=True, label_visibility="collapsed")
        nome = st.text_input("Usuário", placeholder="ex: arthur")
        pin  = st.text_input("PIN (4 dígitos)", type="password", max_chars=4, placeholder="••••")

        if modo == "Entrar":
            if st.button("Entrar →", type="primary", use_container_width=True):
                if not nome or not pin:
                    st.error("Preencha usuário e PIN.")
                elif not user_exists(nome):
                    st.error("Usuário não encontrado.")
                elif not verify_pin(nome, pin):
                    st.error("PIN incorreto.")
                else:
                    st.session_state["usuario"] = nome
                    st.rerun()
        else:
            if st.button("Criar conta →", type="primary", use_container_width=True):
                if not nome:
                    st.error("Digite um nome de usuário.")
                elif len(pin) != 4 or not pin.isdigit():
                    st.error("PIN deve ter 4 dígitos numéricos.")
                elif user_exists(nome):
                    st.error("Usuário já existe. Escolha outro nome.")
                else:
                    create_user(nome, pin)
                    st.session_state["usuario"] = nome
                    st.rerun()

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

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Gastos por categoria")
        if not gastos.empty:
            by_cat = gastos.groupby("categoria")["abs"].sum().reset_index()
            by_cat.columns = ["Categoria", "Total"]
            fig = px.pie(by_cat.sort_values("Total", ascending=False),
                         names="Categoria", values="Total", hole=0.45,
                         color_discrete_sequence=px.colors.qualitative.Set2)
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(showlegend=False, margin=dict(t=10, b=0))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Sem gastos registrados neste período.")

    with col2:
        st.subheader("Gastos por dia")
        if not gastos.empty:
            by_day = gastos.groupby(gastos["data"].dt.date)["abs"].sum().reset_index()
            by_day.columns = ["Data", "Total"]
            fig2 = px.bar(by_day, x="Data", y="Total", color_discrete_sequence=["#8b5cf6"])
            fig2.update_layout(xaxis_title="", yaxis_title="R$", margin=dict(t=10, b=0))
            st.plotly_chart(fig2, use_container_width=True)
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

    edited = st.data_editor(
        tbl[["✓", "Data", "Valor", "Tipo", "Descrição", "Categoria"]],
        column_config={
            "✓":         st.column_config.CheckboxColumn("✓", width="small"),
            "Data":      st.column_config.Column(disabled=True),
            "Valor":     st.column_config.Column(disabled=True),
            "Tipo":      st.column_config.Column(disabled=True, width="small"),
            "Descrição": st.column_config.Column(disabled=True),
            "Categoria": st.column_config.Column(disabled=True),
        },
        hide_index=True, use_container_width=True, key="tx_editor",
    )

    selecionados = uid_index[edited[edited["✓"] == True].index].tolist()
    n = len(selecionados)

    if n > 0:
        st.info(f"**{n} transação(ões) selecionada(s)** — escolha uma ação abaixo:")
        a1, a2, a3 = st.columns([3, 1, 1])
        with a1:
            cat_acao = st.selectbox("Definir categoria", user_cats, key="bulk_cat")
        with a2:
            if st.button("✅ Aplicar categoria", use_container_width=True):
                save_categorias([(uid, cat_acao) for uid in selecionados], usuario)
                fetch_data.clear()
                st.rerun()
        with a3:
            if st.button("🚫 Ignorar selecionados", use_container_width=True):
                save_categorias([(uid, "Ignorar") for uid in selecionados], usuario)
                fetch_data.clear()
                st.rerun()
    else:
        st.caption("Marque ✓ em uma ou mais transações para aplicar uma ação em lote.")

    rows_h, _ = db_exec("SELECT 1 FROM historico WHERE usuario=:u LIMIT 1", {"u": usuario}, fetch=True)
    if rows_h:
        if st.button("↩️ Desfazer última alteração de categorias"):
            n_revert = undo_last_tx(usuario)
            fetch_data.clear()
            st.success(f"{n_revert} transação(ões) revertida(s).")
            st.rerun()

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
    rendas_df = fetch_rendas(usuario)
    edited_rendas = st.data_editor(
        rendas_df, num_rows="dynamic",
        column_config={
            "Fonte de renda": st.column_config.TextColumn(width="large"),
            "Valor (R$)":     st.column_config.NumberColumn(min_value=0.0, step=0.01, format="R$ %.2f"),
        },
        hide_index=True, use_container_width=True, key="rendas_editor",
    )
    if st.button("💾 Salvar renda", key="salvar_rendas"):
        save_rendas(edited_rendas, usuario)
        fetch_rendas.clear()
        st.toast("Renda salva!", icon="✅")
        st.rerun()

    total_renda = edited_rendas["Valor (R$)"].sum()

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
    fig.update_layout(xaxis_title="", yaxis_title="R$", legend_title="Categoria")
    st.plotly_chart(fig, use_container_width=True)

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
def main():
    db_init()

    if "usuario" not in st.session_state:
        render_login()
        return

    usuario = st.session_state["usuario"]

    with st.sidebar:
        st.title("💜 Nubank Tracker")
        col_u, col_s = st.columns([3, 1])
        col_u.caption(f"👤 {usuario}")
        if col_s.button("Sair"):
            del st.session_state["usuario"]
            st.rerun()

        file = st.file_uploader("Importar extrato (.csv)", type="csv")
        if file:
            rows = parse_csv(file, load_rules(usuario))
            n = import_rows(rows, usuario)
            fetch_data.clear()
            if n:
                st.success(f"✅ {n} transações importadas!")
                st.rerun()
            else:
                st.info("Nenhuma transação nova.")

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
        EXCLUIR_CONFIG = [
            ("Fatura Cartão", True), ("Investimento", True),
            ("Resgate RDB",   True), ("Ignorar",      True),
            ("Entrada",      False), ("Pix Recebido", False),
            ("Pix Enviado",  False), ("Transporte",   False),
            ("Alimentação",  False), ("Saúde",        False),
            ("Telefone/Internet", False), ("Dívidas/Boletos", False),
            ("Outros",       False),
        ]
        cats_excluir = []
        c1, c2 = st.columns(2)
        for i, (cat, default) in enumerate(EXCLUIR_CONFIG):
            col = c1 if i % 2 == 0 else c2
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

    rules = load_rules(usuario)
    user_cats = list(ALL_CATS)
    for cat in rules:
        if cat not in user_cats:
            user_cats.append(cat)

    t1, t2, t3, t4, t5 = st.tabs(
        ["📊 Dashboard", "💰 Orçamento", "📈 Histórico", "🔄 Recorrentes", "⚙️ Regras"]
    )
    with t1: render_dashboard(df_all, periodo_sel, cats_excluir, usuario, user_cats)
    with t2: render_orcamento(df_all, usuario, user_cats)
    with t3: render_historico(df_all, user_cats)
    with t4: render_recorrentes(df_all)
    with t5: render_regras(rules, usuario, user_cats)


if __name__ == "__main__":
    main()
