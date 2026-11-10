// Run with: node --test tests/web_agent_dom.cjs
// Exercise actual event handlers against the DOM operations used by the live view.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.className = ''; this.value = ''; }
  set textContent(value) { this.value = String(value); this.children = []; }
  get textContent() { return this.value + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw Error('Telemetry must never use innerHTML'); }
  append(...nodes) { for (const node of nodes) { node.parentElement = this; this.children.push(node); } }
  prepend(node) { node.parentElement = this; this.children.unshift(node); }
  replaceChildren(...nodes) { this.children = []; this.value = ''; this.append(...nodes); }
  remove() { const index = this.parentElement.children.indexOf(this); this.parentElement.children.splice(index, 1); }
  get lastElementChild() { return this.children.at(-1); }
  contains(node) { return node === this || this.children.some(child => child.contains(node)); }
  getAttribute(name) { return this[name]; }
  closest(selector) { return selector.toUpperCase().split(/,\s*/).includes(this.tagName) ? this : this.parentElement?.closest(selector); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    const matches = node => {
      if (selector === 'a[href^="/findings/"]') return node.tagName === 'A' && (node.href || '').startsWith('/findings/');
      if (selector === 'a[data-finding-id]') return node.tagName === 'A' && node.dataset.findingId !== undefined;
      if (selector.startsWith('.')) return node.className.split(' ').includes(selector.slice(1));
      throw Error('Unsupported DOM selector: ' + selector);
    };
    return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
}

function fixture() {
  const document = new Element('document');
  const ids = Object.fromEntries(['live', 'live-state', 'feed', 'newfeed', 'agent-activity'].map(id => [id, new Element('div')]));
  ids.live.dataset.stream = '/hunts/h1/stream?after_seq=15';
  ids.live.dataset.live = 'true';
  document.append(...Object.values(ids));
  document.getElementById = id => ids[id];
  document.createElement = tag => new Element(tag);
  let source;
  class EventSource {
    constructor() { source = this; this.listeners = {}; this.closed = false; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    close() { this.closed = true; }
    emit(name, payload) { this.listeners[name]({data: JSON.stringify(payload)}); }
  }
  const start = () => {
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/romulus/web/static/app.js'), 'utf8'),
      {document, window: {EventSource}, EventSource});
    return source;
  };
  return {document, ids, start};
}

const finding = (id, extra = {}) => ({id, lane: 'high', rule: 'agent.finding', claim: '<script>untrusted</script>',
  revised: false, provenance: 'agent', ...extra});

test('new and revised live agent findings are unconfirmed text and remain bounded', () => {
  const {ids, start} = fixture();
  const source = start();
  source.emit('finding', finding('new'));
  assert.match(ids.feed.textContent, /AI agent · unconfirmed/);
  source.emit('finding', finding('new', {revised: true, claim: 'Revised claim'}));
  assert.equal(ids.feed.children.length, 1);
  assert.match(ids.feed.textContent, /AI agent · unconfirmed/);
  assert.match(ids.feed.textContent, /Revised claim/);
  for (let index = 0; index < 55; index++) source.emit('finding', finding(String(index)));
  assert.equal(ids.feed.children.length, 50);
  source.emit('agent_finding', finding('activity'));
  assert.match(ids['agent-activity'].textContent, /AI agent · unconfirmed/);
  source.emit('state', {state: 'completed_within_scope'});
  assert.equal(source.closed, false);
  source.emit('end', {});
  assert.equal(source.closed, true);
});

test('assessment citations neither swallow findings nor receive row revisions', () => {
  const {document, ids, start} = fixture();
  const citation = new Element('a'); citation.href = '/findings/existing'; citation.textContent = 'Assessment cite';
  const offPage = new Element('a'); offPage.href = '/findings/off-page'; offPage.textContent = 'Other cite';
  document.append(citation, offPage);
  const row = new Element('tr'), cell = new Element('td'), pill = new Element('span'), link = new Element('a');
  pill.className = 'pill l-lead'; pill.textContent = 'lead';
  link.href = '/findings/existing'; link.dataset.findingId = 'existing'; link.textContent = 'Old finding';
  cell.append(pill, link); row.append(cell); document.append(row);
  const source = start();
  source.emit('finding', finding('existing', {revised: true, claim: 'Changed actual finding'}));
  assert.equal(citation.textContent, 'Assessment cite');
  assert.match(link.textContent, /Changed actual finding/);
  assert.equal(pill.textContent, 'high');
  source.emit('finding', finding('off-page'));
  assert.equal(ids.feed.children.length, 1);
  assert.equal(offPage.textContent, 'Other cite');
});


test('terminal view never opens an EventSource', () => {
  const {ids, start} = fixture();
  ids.live.dataset.live = 'false';
  assert.equal(start(), undefined);
});
