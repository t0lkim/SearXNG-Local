// AI overview panel (browser side). Model output is untrusted: it is only ever inserted as text,
// and the only links created are [n] citations pointing at the source URLs this page sent.

// Splits an answer into text and citation segments; citations outside 1..sourceCount stay as text
export function segments(answer, sourceCount) {
  const out = [];
  let last = 0;
  for (const m of answer.matchAll(/\[(\d{1,2})\]/g)) {
    const n = Number(m[1]);
    if (n < 1 || n > sourceCount) continue;
    if (m.index > last) out.push({ type: "text", text: answer.slice(last, m.index) });
    out.push({ type: "cite", n });
    last = m.index + m[0].length;
  }
  if (last < answer.length) out.push({ type: "text", text: answer.slice(last) });
  return out;
}

if (typeof document !== "undefined") {
  const panel = document.getElementById("ai-overview");
  if (panel) start(panel);
}

function start(panel) {
  const query = panel.dataset.query;
  const providers = JSON.parse(panel.dataset.providers || "[]");
  let provider = panel.dataset.provider;
  const sources = [...document.querySelectorAll("#urls article.result")]
    .map(a => ({
      title: a.querySelector("h3 a")?.textContent.trim() ?? "",
      url: a.querySelector("h3 a")?.href ?? "",
      snippet: a.querySelector("p.content")?.textContent.trim() ?? "",
    }))
    .filter(s => /^https?:\/\//.test(s.url))
    .slice(0, 8);
  if (sources.length === 0) { panel.remove(); return; }

  let history = [];

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };

  const head = el("div", "aio-head");
  head.append(el("span", "aio-title", "AI overview"));
  const badge = el("span", "aio-badge");
  const switcher = el("span", "aio-switch");
  head.append(badge, switcher);
  let status = null;
  fetch("/api/ai-status").then(r => r.json()).then(s => { status = s; renderBadge(); }).catch(() => {});

  // Shows who pays for the answer: the ChatGPT subscription, an API key billed per use, or the local machine
  function renderBadge() {
    const labels = {
      "subscription": ["ChatGPT subscription", "aio-sub"],
      "api-key": ["OpenAI API key · billed per use", "aio-api"],
      "signed-out": ["Codex not signed in", "aio-bad"],
      "unavailable": ["Codex unavailable", "aio-bad"],
    };
    const [text, cls] = provider === "ollama"
      ? [status?.ollamaModel ? `Local · ${status.ollamaModel}` : "Local · no model set", status?.ollamaModel ? "aio-sub" : "aio-bad"]
      : (labels[status?.codex] ?? ["checking sign-in…", ""]);
    badge.textContent = text;
    badge.className = `aio-badge ${cls}`;
    badge.title = provider === "codex" ? "From: codex login status" : "From: SEARXNG_OLLAMA_MODEL";
  }
  const thread = el("div", "aio-thread");
  const form = el("form", "aio-ask");
  const input = el("input");
  input.type = "text";
  input.placeholder = "Ask a follow-up about these results";
  form.append(input, Object.assign(el("button", "", "Ask"), { type: "submit" }));
  panel.append(head, thread, form);

  function renderSwitch() {
    switcher.replaceChildren(...providers.map(p => {
      const b = el("button", p === provider ? "aio-on" : "", p === "codex" ? "ChatGPT" : "Local");
      b.type = "button";
      b.onclick = () => { if (p !== provider) { provider = p; history = []; thread.replaceChildren(); renderSwitch(); renderBadge(); ask(""); } };
      return b;
    }));
  }

  function renderAnswer(box, answer) {
    box.replaceChildren();
    for (const para of answer.split(/\n{2,}/)) {
      const p = el("p");
      for (const s of segments(para, sources.length)) {
        if (s.type === "text") p.append(document.createTextNode(s.text));
        else {
          const a = el("a", "aio-cite", `[${s.n}]`);
          a.href = sources[s.n - 1].url;
          a.title = sources[s.n - 1].title;
          a.rel = "noreferrer";
          p.append(a);
        }
      }
      box.append(p);
    }
  }

  async function ask(question) {
    if (question) thread.append(el("div", "aio-q", question));
    const box = el("div", "aio-a aio-wait", provider === "codex" ? "Asking ChatGPT… (usually 10 to 20 s)" : "Asking the local model…");
    thread.append(box);
    form.querySelector("button").disabled = true;
    try {
      const res = await fetch("/api/overview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, sources, provider, history, question }),
      });
      const data = await res.json();
      box.classList.remove("aio-wait");
      if (!data.ok) { box.classList.add("aio-err"); box.textContent = `No answer: ${data.error}`; return; }
      renderAnswer(box, data.answer);
      history.push({ question: question || query, answer: data.answer });
    } catch (e) {
      box.classList.remove("aio-wait");
      box.classList.add("aio-err");
      box.textContent = `No answer: ${e.message}`;
    } finally {
      form.querySelector("button").disabled = false;
    }
  }

  form.onsubmit = e => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    input.value = "";
    ask(q);
  };

  renderSwitch();
  ask("");
}
