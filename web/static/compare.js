/* The compare page (web/compare.py): asks /api/scan once per site and draws the scores and the check-by-check table.
   Every word comes from the page's JSON block, and every value from the server is written as text, never as HTML. */
(function () {
  var dataEl = document.getElementById('cmp-data'), form = document.getElementById('cmp-form');
  var fields = document.getElementById('cmp-fields'), addBtn = document.getElementById('cmp-add');
  var goBtn = document.getElementById('cmp-go'), errorEl = document.getElementById('cmp-error');
  var statusEl = document.getElementById('cmp-status'), result = document.getElementById('cmp-result');
  if (!dataEl || !form || !fields || !result) return;
  var cfg = JSON.parse(dataEl.textContent), w = cfg.words;
  var GRADE = { A: '#047857', B: '#15803d', C: '#b45309', D: '#c2410c', F: '#b91c1c' };
  var MARK = { ok: '✓', warn: '!', fail: '✕', info: 'i', none: '–' };
  var RANK = { fail: 0, warn: 1, ok: 2, info: 3 };
  var submitText = goBtn.textContent, run = 0, onlyDiff = true;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function fill(template, values) {
    return template.replace(/\{(\w+)\}/g, function (_, k) { return values[k]; });
  }
  // example.az, https://www.Example.az/ and example.az/page are the same site for "entered twice"
  function key(value) {
    return value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  }
  function inputs() { return [].slice.call(fields.querySelectorAll('input')); }
  function showError(text) { errorEl.textContent = text; errorEl.hidden = !text; }

  function renumber() {
    [].forEach.call(fields.children, function (box, i) {
      var input = box.querySelector('input'), label = box.querySelector('label');
      input.id = 'cmp-u' + (i + 1);
      input.placeholder = cfg.placeholders[i];
      label.htmlFor = input.id;
      label.textContent = '';
      var n = el('span', 'num', String(i + 1));
      n.setAttribute('aria-hidden', 'true');
      label.appendChild(n);
      label.appendChild(document.createTextNode(cfg.labels[i]));
    });
    addBtn.hidden = fields.children.length >= cfg.max;
  }
  function addField(value) {
    if (fields.children.length >= cfg.max) return null;
    var box = el('div', 'cmp-field'), label = el('label'), row = el('div', 'cmp-row'), input = el('input');
    input.name = 'u'; input.type = 'text'; input.maxLength = 300; input.spellcheck = false;
    input.setAttribute('inputmode', 'url'); input.setAttribute('autocomplete', 'off'); input.setAttribute('autocapitalize', 'off');
    input.value = value || '';
    var x = el('button', 'cmp-x', '×');
    x.type = 'button';
    x.setAttribute('aria-label', w.remove);
    x.addEventListener('click', function () {
      fields.removeChild(box);
      renumber();
      addBtn.focus();
    });
    row.appendChild(input); row.appendChild(x);
    box.appendChild(label); box.appendChild(row);
    fields.appendChild(box);
    renumber();
    return input;
  }

  function scan(url) {
    return fetch('/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, lang: cfg.lang })
    }).then(function (res) {
      return res.json().then(function (body) {
        if (res.ok) return { report: body };
        return { error: typeof body.detail === 'string' ? body.detail : w.generic };
      }, function () { return { error: w.generic }; });
    }, function () { return { error: w.network }; });
  }

  function hostOf(report, typed) {
    return (report.display_url || report.final_url || typed).replace(/^https?:\/\//, '').replace(/\/$/, '');
  }
  function card(i, typed) {
    var c = el('article', 'cmp-card'), h = el('h3');
    h.appendChild(el('span', 'num', String(i + 1)));
    var name = el('span', null, key(typed) || typed);
    h.appendChild(name);
    c.appendChild(h);
    var body = el('div');
    body.appendChild(el('div', 'spin'));
    body.appendChild(el('p', null, w.checking));
    c.appendChild(body);
    return { box: c, name: name, body: body };
  }
  function fillCard(view, site, typed) {
    view.body.textContent = '';
    if (site.error) {
      view.body.appendChild(el('p', null, w.failed + ': ')).appendChild(el('span', null, site.error));
      return;
    }
    var r = site.report, color = GRADE[r.grade] || '#64748b', counts = r.counts || {};
    view.box.style.setProperty('--c', color);
    view.name.textContent = hostOf(r, typed);
    var score = el('div', 'cmp-score');
    score.appendChild(el('b', null, String(r.score)));
    score.appendChild(el('small', null, '/100'));
    view.body.appendChild(score);
    var bar = el('div', 'cmp-bar'), inner = el('i');
    bar.appendChild(inner);
    view.body.appendChild(bar);
    setTimeout(function () { inner.style.width = Math.max(2, r.score) + '%'; }, 30);
    view.body.appendChild(el('span', 'cmp-grade', w.grade + ': ' + r.grade));
    var list = el('ul', 'cmp-counts');
    [['fail', counts.fail], ['warn', counts.warn], ['ok', counts.ok]].forEach(function (row) {
      var li = el('li');
      li.appendChild(el('i', 'dot ' + row[0]));
      li.appendChild(document.createTextNode((row[1] || 0) + ' ' + w[row[0]]));
      list.appendChild(li);
    });
    view.body.appendChild(list);
    var link = el('a', null, w.full);
    link.href = cfg.home + '?url=' + encodeURIComponent(typed);
    view.body.appendChild(el('p')).appendChild(link);
  }

  function statusCell(status) {
    var td = el('td'), kind = status || 'none';
    var mark = el('span', 'st ' + kind, MARK[kind]);
    mark.setAttribute('aria-hidden', 'true');
    td.appendChild(mark);
    td.appendChild(el('span', 'sr', w['st_' + kind]));
    return td;
  }
  function headRow(first, sites) {
    var tr = el('tr'), th = el('th', null, first);
    th.scope = 'col';
    tr.appendChild(th);
    sites.forEach(function (s) {
      var h = el('th');
      h.scope = 'col';
      h.appendChild(el('span', 'num', String(s.index + 1)));
      h.appendChild(el('span', 'sr', ' ' + s.host));
      h.title = s.host;
      tr.appendChild(h);
    });
    return tr;
  }
  function table(head) {
    var wrap = el('div', 'tw'), t = el('table', 'cmp-table'), thead = el('thead'), tbody = el('tbody');
    wrap.tabIndex = 0;
    thead.appendChild(head);
    t.appendChild(thead); t.appendChild(tbody);
    wrap.appendChild(t);
    return { wrap: wrap, body: tbody };
  }

  function drawTables(box, sites) {
    // every check any of the sites has, in the order of the scanner's categories
    var order = [], seen = {}, cats = [];
    sites.forEach(function (s) {
      s.byId = {};
      s.report.findings.forEach(function (f) {
        s.byId[f.id] = f;
        if (!seen[f.id]) { seen[f.id] = true; order.push({ id: f.id, title: f.title, category: f.category }); }
        if (cats.indexOf(f.category) < 0) cats.push(f.category);
      });
    });

    box.appendChild(el('h2', 'cmp-h', w.categories));
    var ct = table(headRow(w.category, sites));
    cats.forEach(function (cat) {
      var tr = el('tr'), th = el('th', null, cat), cells = [];
      th.scope = 'row';
      tr.appendChild(th);
      sites.forEach(function (s) {
        var counted = s.report.findings.filter(function (f) { return f.category === cat && f.status !== 'info'; });
        var ok = counted.filter(function (f) { return f.status === 'ok'; }).length;
        var td = el('td', null, counted.length ? ok + '/' + counted.length : '–');
        td.appendChild(el('span', 'sr', ' ' + fill(w.passed, { n: ok, total: counted.length })));
        cells.push({ td: td, share: counted.length ? ok / counted.length : -1 });
        tr.appendChild(td);
      });
      var top = Math.max.apply(null, cells.map(function (c) { return c.share; }));
      if (cells.some(function (c) { return c.share !== top; })) {
        cells.forEach(function (c) { if (c.share === top) c.td.className = 'best'; });
      }
      ct.body.appendChild(tr);
    });
    box.appendChild(ct.wrap);

    box.appendChild(el('h2', 'cmp-h', w.checks));
    var note = el('p', 'cmp-sub');
    box.appendChild(note);
    var legend = el('p', 'cmp-legend');
    legend.setAttribute('aria-label', w.legend);
    ['fail', 'warn', 'ok', 'info'].forEach(function (k) {
      var item = el('span');
      var mark = el('span', 'st ' + k, MARK[k]);
      mark.setAttribute('aria-hidden', 'true');
      item.appendChild(mark);
      item.appendChild(document.createTextNode(w['st_' + k]));
      legend.appendChild(item);
    });
    box.appendChild(legend);
    var kt = table(headRow(w.check, sites)), rows = [], differing = 0;
    cats.forEach(function (cat) {
      var head = el('tr', 'cat'), hth = el('th', null, cat);
      hth.colSpan = sites.length + 1;
      hth.scope = 'colgroup';
      head.appendChild(hth);
      kt.body.appendChild(head);
      var group = { head: head, rows: [] };
      order.filter(function (c) { return c.category === cat; }).map(function (c) {
        var statuses = sites.map(function (s) { return s.byId[c.id] ? s.byId[c.id].status : null; });
        var worst = Math.min.apply(null, statuses.map(function (st) { return st ? RANK[st] : 9; }));
        return { check: c, statuses: statuses, worst: worst, same: statuses.every(function (st) { return st === statuses[0]; }) };
      }).sort(function (a, b) { return a.worst - b.worst; }).forEach(function (r) {
        var tr = el('tr'), th = el('th', null, r.check.title);
        th.scope = 'row';
        tr.appendChild(th);
        r.statuses.forEach(function (st) { tr.appendChild(statusCell(st)); });
        kt.body.appendChild(tr);
        group.rows.push({ tr: tr, same: r.same });
        differing += !r.same;
      });
      rows.push(group);
    });
    box.appendChild(kt.wrap);

    var tools = el('div', 'cmp-tools'), toggle = el('button', 'b b-ghost'), copy = el('button', 'b b-ghost', w.copy);
    var clear = el('button', 'b b-ghost', w.clear);
    toggle.type = copy.type = clear.type = 'button';
    function apply() {
      var diffOnly = onlyDiff && differing > 0;
      rows.forEach(function (g) {
        var shown = 0;
        g.rows.forEach(function (r) { r.tr.hidden = diffOnly && r.same; shown += !r.tr.hidden; });
        g.head.hidden = !shown;
      });
      note.textContent = differing ? (diffOnly ? w.only_diff : '') : w.no_diff;
      note.hidden = !note.textContent;
      toggle.textContent = diffOnly ? fill(w.show_all, { n: order.length }) : w.show_diff;
      toggle.hidden = !differing;
    }
    toggle.addEventListener('click', function () { onlyDiff = !onlyDiff; apply(); });
    copy.addEventListener('click', function () {
      var done = function () { copy.textContent = w.copied; setTimeout(function () { copy.textContent = w.copy; }, 2000); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(location.href).then(done, function () { window.prompt(w.copy, location.href); });
      } else window.prompt(w.copy, location.href);
    });
    clear.addEventListener('click', reset);
    tools.appendChild(toggle); tools.appendChild(copy); tools.appendChild(clear);
    box.appendChild(tools);
    apply();
  }

  function reset() {
    run++;
    result.hidden = true;
    result.textContent = '';
    statusEl.textContent = '';
    showError('');
    inputs().forEach(function (input) { input.value = ''; });
    try { history.replaceState(null, '', location.pathname); } catch (e) { /* the link simply stays */ }
    goBtn.disabled = false;
    goBtn.textContent = submitText;
    inputs()[0].focus();
  }

  function compare() {
    var typed = inputs().map(function (i) { return i.value.trim(); }).filter(Boolean);
    showError('');
    if (typed.length < 2) { showError(w.need_two); (inputs().filter(function (i) { return !i.value.trim(); })[0] || inputs()[0]).focus(); return; }
    var keys = typed.map(key);
    if (keys.some(function (k, i) { return keys.indexOf(k) !== i; })) { showError(w.duplicate); return; }
    var mine = ++run;
    var query = typed.map(function (u) { return 'u=' + encodeURIComponent(u); }).join('&');
    try { history.replaceState(null, '', location.pathname + '?' + query); } catch (e) { /* the link simply stays */ }
    goBtn.disabled = true;
    goBtn.textContent = w.checking;
    statusEl.textContent = w.checking_all;
    result.textContent = '';
    result.hidden = false;
    var verdict = el('h2', 'cmp-verdict'), cards = el('div', 'cmp-cards'), tables = el('div');
    verdict.hidden = true;
    result.appendChild(verdict); result.appendChild(cards); result.appendChild(tables);
    var views = typed.map(function (u, i) { var v = card(i, u); cards.appendChild(v.box); return v; });
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });

    Promise.all(typed.map(function (u, i) {
      return scan(u).then(function (site) {
        if (mine === run) fillCard(views[i], site, u);
        site.index = i;
        site.typed = u;
        return site;
      });
    })).then(function (all) {
      if (mine !== run) return;
      goBtn.disabled = false;
      goBtn.textContent = submitText;
      var good = all.filter(function (s) { return s.report; });
      good.forEach(function (s) { s.host = hostOf(s.report, s.typed); });
      if (good.length < 2) { statusEl.textContent = ''; showError(good.length ? w.one_ok : w.none_ok); return; }
      var sorted = good.slice().sort(function (a, b) { return b.report.score - a.report.score; });
      var top = sorted[0], diff = top.report.score - sorted[1].report.score;
      verdict.textContent = diff ? fill(w.leader, { host: top.host, score: top.report.score, diff: diff }) : fill(w.tie, { score: top.report.score });
      verdict.hidden = false;
      if (diff) views[top.index].box.className += ' lead-card';
      drawTables(tables, good);
      statusEl.textContent = w.done;
    });
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); compare(); });
  addBtn.addEventListener('click', function () { var input = addField(''); if (input) input.focus(); });
  addBtn.hidden = false;

  // ?u=a.az&u=b.az starts the comparison straight away, so a copied link shows the same result
  var asked = new URLSearchParams(location.search).getAll('u').filter(Boolean).slice(0, cfg.max);
  asked.forEach(function (u, i) {
    var input = inputs()[i] || addField('');
    if (input) input.value = u;
  });
  if (asked.length >= 2) compare();
})();
