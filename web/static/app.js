(function () {
  "use strict";

  // Your WhatsApp number in international format, digits only (e.g. "994501234567").
  // Leave empty to hide the WhatsApp button.
  var WA_NUMBER = "994772172358";

  var $ = function (id) { return document.getElementById(id); };
  var form = $("form"), input = $("url"), go = $("go"), err = $("err");
  var loading = $("loading"), report = $("report");
  var ICON = { fail: "i-x", warn: "i-warn", ok: "i-check", info: "i-info" };
  var LABEL = { fail: "Ciddi problem", warn: "Tövsiyə", ok: "Qaydasındadır", info: "Məlumat" };
  var GRADE_COLOR = { A: "#059669", B: "#16a34a", C: "#d97706", D: "#ea580c", F: "#dc2626" };
  var STEPS = ["Sayta qoşuluruq…", "Sertifikat yoxlanılır…", "Təhlükəsizlik ayarları yoxlanılır…",
               "E-poçt qorumasına baxılır…", "Hesabat hazırlanır…"];

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // ---------------- guide
  var guide = $("guide"), lastFocus = null;
  function openGuide() { lastFocus = document.activeElement; guide.hidden = false; document.body.style.overflow = "hidden"; $("guideClose").focus(); }
  function closeGuide() { guide.hidden = true; document.body.style.overflow = ""; if (lastFocus) lastFocus.focus(); }
  document.querySelectorAll("[data-guide]").forEach(function (b) { b.addEventListener("click", openGuide); });
  $("guideClose").addEventListener("click", closeGuide);
  $("guideStart").addEventListener("click", function () { closeGuide(); input.focus(); window.scrollTo({ top: 0, behavior: "smooth" }); });
  guide.addEventListener("click", function (e) { if (e.target === guide) closeGuide(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !guide.hidden) closeGuide(); });

  // ---------------- scan
  var timer = null;
  function setLoading(on) {
    go.disabled = on; go.textContent = on ? "Yoxlanılır…" : "Yoxla";
    loading.hidden = !on;
    clearInterval(timer);
    if (on) {
      var i = 0; $("loadingText").textContent = STEPS[0];
      timer = setInterval(function () { i = Math.min(i + 1, STEPS.length - 1); $("loadingText").textContent = STEPS[i]; }, 2500);
      loading.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }
  function showError(msg) { err.textContent = msg; err.hidden = false; }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var url = input.value.trim();
    err.hidden = true;
    if (!url) { showError("Əvvəlcə saytınızın ünvanını yazın. Məsələn: meninsaytim.az"); input.focus(); return; }
    report.hidden = true;
    setLoading(true);
    fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: url }) })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        setLoading(false);
        if (!res.ok) { showError(res.d.detail || "Xəta baş verdi. Bir az sonra yenidən cəhd edin."); return; }
        render(res.d);
      })
      .catch(function () { setLoading(false); showError("Serverə qoşulmaq mümkün olmadı. İnternet bağlantınızı yoxlayın."); });
  });

  function findingHTML(f) {
    return '<div class="f ' + f.status + '">' +
      '<span class="si" aria-hidden="true"><svg class="ico"><use href="#' + ICON[f.status] + '"/></svg></span>' +
      '<div><h4>' + esc(f.title) + '<span class="lbl">' + LABEL[f.status] + '</span></h4>' +
      '<p>' + esc(f.detail) + '</p>' +
      (f.fix ? '<div class="fix"><strong>Necə düzəltmək</strong>' + esc(f.fix) + '</div>' : '') +
      '</div></div>';
  }

  function render(d) {
    var g = d.grade, color = GRADE_COLOR[g] || "#059669";
    $("score").textContent = d.score;
    var ring = $("scoreRing"); ring.style.setProperty("--c", color); ring.style.setProperty("--p", 0);
    requestAnimationFrame(function () { ring.style.transition = "none"; animate(ring, d.score); });
    var gr = $("grade"); gr.textContent = "Qiymət: " + g; gr.style.background = color;
    $("repUrl").textContent = d.final_url.replace(/^https?:\/\//, "").replace(/\/$/, "");
    $("summary").textContent = d.summary;
    var c = d.counts || {};
    $("chips").innerHTML =
      (c.fail ? '<span class="chip fail">' + c.fail + ' ciddi problem</span>' : '') +
      (c.warn ? '<span class="chip warn">' + c.warn + ' tövsiyə</span>' : '') +
      '<span class="chip ok">' + (c.ok || 0) + ' qaydasında</span>';

    var ORDER = ["Təhlükəsizlik", "E-poçt", "Sürət", "Mobil və Google"];
    var cats = [];
    d.findings.forEach(function (f) { if (cats.indexOf(f.category) < 0) cats.push(f.category); });
    cats.sort(function (a, b) { return ORDER.indexOf(a) - ORDER.indexOf(b); });
    $("groups").innerHTML = cats.map(function (cat) {
      var items = d.findings.filter(function (f) { return f.category === cat; });
      var bad = items.filter(function (f) { return f.status === "fail" || f.status === "warn"; });
      var rest = items.filter(function (f) { return f.status !== "fail" && f.status !== "warn"; });
      return '<div class="group"><h3>' + esc(cat) + ' <small>' + (bad.length ? bad.length + ' məsələ' : 'hər şey qaydasındadır') + '</small></h3>' +
        bad.map(findingHTML).join("") +
        (rest.length ? (bad.length ? '<details class="ok-list"><summary>+ ' + rest.length + ' qaydasında olan yoxlamanı göstər</summary>' + rest.map(findingHTML).join("") + '</details>'
                                   : rest.map(findingHTML).join("")) : '') +
        '</div>';
    }).join("");

    var when = new Date(d.scanned_at);
    $("scannedAt").textContent = "Yoxlama vaxtı: " + when.toLocaleString("az-AZ") + ". Nəticə yalnız açıq məlumatlara əsaslanır.";

    var cta = $("cta");
    var clean = !c.fail && !c.warn;
    cta.querySelector("h3").textContent = clean ? "Saytınız əla vəziyyətdədir!" : "Problemləri özünüz düzəldə bilmirsiniz?";
    cta.querySelector("p").textContent = clean
      ? "Yeni sayt, dizayn yeniləməsi və ya saytın mütəmadi izlənməsi lazımdırsa, yazın."
      : "Hesabatı göndərin, nəyin necə düzəldiləcəyini izah edək və ya özümüz düzəldək.";
    if (WA_NUMBER) {
      var msg = "Salam! SaytYoxla-da " + $("repUrl").textContent + " saytını yoxladım: " + d.score + "/100 (" + g + "). " +
        (clean ? "Sizinlə əməkdaşlıq barədə danışmaq istəyirəm." : "Problemləri düzəltməyə kömək lazımdır.");
      $("waBtn").href = "https://wa.me/" + WA_NUMBER + "?text=" + encodeURIComponent(msg);
      cta.hidden = false;
    } else { cta.hidden = true; }

    report.hidden = false;
    report.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function animate(ring, target) {
    var start = null;
    function step(t) {
      if (!start) start = t;
      var p = Math.min(1, (t - start) / 900);
      ring.style.setProperty("--p", Math.round(target * p));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  $("print").addEventListener("click", function () {
    report.querySelectorAll("details").forEach(function (d) { d.open = true; });
    window.print();
  });
  $("again").addEventListener("click", function () {
    report.hidden = true; input.value = ""; window.scrollTo({ top: 0, behavior: "smooth" }); input.focus();
  });

  // ?url=example.az starts a scan straight away (handy for sharing)
  var q = new URLSearchParams(location.search).get("url");
  if (q) { input.value = q; form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit")); }
})();
