const template = document.createElement('template');
template.innerHTML = `
  <style>
    :host {
      display: block;
    }
  </style>
  <div id="user-files">
    <h3>User files</h3>
    <button id="loadTexts">load texts</button>
    <ul id="files"></ul>
  </div>
  <div id="new-file">
    <input id="filename" type="text"> <input id="newText" type="submit" value="make new text">
  </div>
`;

export class UserFiles extends HTMLElement {

  static get observedAttributes() {
    return ['user', 'db'];
  }

  constructor() {
    super();
    this.attachShadow({mode: "open"});
    this.shadowRoot.append(template.content.cloneNode(true));
    const newText = this.shadowRoot.querySelector('#newText');
    const loadTexts = this.shadowRoot.querySelector('#loadTexts');
    newText.addEventListener('click', e => this.newText(e));
    loadTexts.addEventListener('click', e => this.loadTexts(e));
  }

  //todo this should likely be a li elements added as children to the host node.
  addTexts(texts) {
    const ul = this.shadowRoot.querySelector("#files");
    ul.innerHTML = '<li>' + texts.join('</li><li>') + '</li>';
  }

  async newText(e) {
    if (e.defaultPrevented)
      return;
    const fileName = this.shadowRoot.querySelector('filename').value;
    const result = await fetch([this.db, 'WRITE', this.user, fileName].join('/'), {
      method: 'POST',
      body: JSON.stringify([{op: 'NEW', data: 'hello sunshine'}])
    });
    if (result.status === 200) {
      const li = document.createElement('li');
      li.innerText = await result.text();
      this.shadowRoot.querySelector("#files").append(li);
    } else {
      alert('wtf');
    }
  }

  async loadTexts(e) {
    const resp = await fetch([this.db, 'FILES', this.user].join('/'));
    const files = await resp.json();
    this.addTexts(files);
  }

  get user() {
    return this.getAttribute('user');
  }

  get db() {
    return this.getAttribute('db');
  }

  attributeChangedCallback(name, newValue, oldValue) {
    if (name === 'user') {
      this.shadowRoot.querySelector('h3').innerText = `User files: ${this.user}`;
    } else if (name === 'db') {
    }
  }
}