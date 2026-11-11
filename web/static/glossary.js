/* Search for the glossary page (az, en, ru): finds terms by word and jumps to the place in the text. */
(function () {
  var box = document.getElementById('gl-search'), q = document.getElementById('gl-q');
  var list = document.getElementById('gl-results'), status = document.getElementById('gl-status');
  var text = document.getElementById('gl-text');
  if (!box || !q || !list || !text) return;
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  // the sentences shown under the box come from the page, in its language (web/glossary.py)
  function say(name, mark, value) { var t = box.getAttribute('data-' + name) || ''; return mark ? t.split(mark).join(String(value)) : t; }
  var MAP = { 'ə': 'e', 'ı': 'i', 'ö': 'o', 'ü': 'u', 'ş': 's', 'ç': 'c', 'ğ': 'g', 'ё': 'е' };
  // every replaced letter is one character, so positions in the normalized text match the original
  function norm(s) { return String(s).toLowerCase().replace(/[əıöüşçğё]/g, function (c) { return MAP[c]; }); }
  var terms = [].slice.call(text.querySelectorAll('.term')).map(function (el) {
    var h = el.querySelector('h2,h3');
    return { el: el, title: h ? h.textContent : '', t: norm(h ? h.textContent : ''), k: norm(el.getAttribute('data-k') || ''), b: norm(el.textContent) };
  });
  var shown = [], active = -1, lastMarked = [];

  function score(t, words) {
    var s = 0;
    for (var i = 0; i < words.length; i++) {
      var w = words[i], p = 0;
      if (t.t.indexOf(w) === 0 || t.t.indexOf(' ' + w) > -1) p = 100;
      else if (t.t.indexOf(w) > -1) p = 80;
      else if (t.k.indexOf(w) > -1) p = 60;
      else if (t.b.indexOf(w) > -1) p = 20;
      if (!p) return 0;
      s += p;
    }
    return s;
  }
  function clearMarks() {
    lastMarked.forEach(function (m) {
      var p = m.parentNode; if (!p) return;
      p.replaceChild(document.createTextNode(m.textContent), m); p.normalize();
    });
    lastMarked = [];
  }
  function mark(el, words) {
    var walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT), nodes = [], n;
    while ((n = walker.nextNode())) nodes.push(n);
    nodes.forEach(function (node) {
      var raw = node.nodeValue, low = norm(raw), hits = [];
      words.forEach(function (w) { var i = -1; while ((i = low.indexOf(w, i + 1)) > -1) hits.push([i, i + w.length]); });
      if (!hits.length) return;
      hits.sort(function (a, b) { return a[0] - b[0]; });
      var frag = document.createDocumentFragment(), pos = 0;
      hits.forEach(function (h) {
        if (h[0] < pos) return;
        frag.appendChild(document.createTextNode(raw.slice(pos, h[0])));
        var m = document.createElement('mark'); m.textContent = raw.slice(h[0], h[1]); frag.appendChild(m); lastMarked.push(m);
        pos = h[1];
      });
      frag.appendChild(document.createTextNode(raw.slice(pos)));
      node.parentNode.replaceChild(frag, node);
    });
  }
  function words() { return norm(q.value).split(/\s+/).filter(Boolean); }

  function render() {
    var w = words(); list.innerHTML = ''; active = -1; shown = [];
    q.removeAttribute('aria-activedescendant');
    if (!w.length) { list.hidden = true; status.textContent = ''; return; }
    terms.forEach(function (t) { var s = score(t, w); if (s) shown.push({ t: t, s: s }); });
    shown.sort(function (a, b) { return b.s - a.s; });
    shown = shown.slice(0, 12);
    shown.forEach(function (r, i) {
      var li = document.createElement('li'), b = document.createElement('button');
      b.type = 'button'; b.id = 'gl-r' + i; b.setAttribute('role', 'option'); b.setAttribute('aria-selected', 'false'); b.textContent = r.t.title;
      b.addEventListener('click', function () { go(i); });
      li.appendChild(b); list.appendChild(li);
    });
    list.hidden = !shown.length;
    q.setAttribute('aria-expanded', String(!list.hidden));
    status.textContent = shown.length ? say('found', '{n}', shown.length) : say('none');
  }
  function go(i) {
    var r = shown[i]; if (!r) return;
    clearMarks();
    mark(r.t.el, words());
    list.hidden = true; q.setAttribute('aria-expanded', 'false');
    r.t.el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    r.t.el.classList.remove('flash'); void r.t.el.offsetWidth; r.t.el.classList.add('flash');
    try { history.replaceState(null, '', '#' + r.t.el.id); } catch (e) {}
    status.textContent = say('jumped', '{title}', r.t.title);
  }
  function setActive(n) {
    var bs = list.querySelectorAll('button'); if (!bs.length) return;
    active = (n + bs.length) % bs.length;
    [].forEach.call(bs, function (b, i) { b.setAttribute('aria-selected', i === active ? 'true' : 'false'); });
    q.setAttribute('aria-activedescendant', bs[active].id); bs[active].scrollIntoView({ block: 'nearest' });
  }
  q.setAttribute('role', 'combobox'); q.setAttribute('aria-controls', 'gl-results'); q.setAttribute('aria-expanded', 'false');
  q.addEventListener('input', function () { clearMarks(); render(); });
  q.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (e.key === 'Enter') { e.preventDefault(); go(active > -1 ? active : 0); }
    else if (e.key === 'Escape') { q.value = ''; clearMarks(); render(); }
  });
  box.hidden = false;
  if (location.hash.length > 1) {
    var t = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (t) setTimeout(function () { t.scrollIntoView(); }, 0);
  }
})();
