import {aPopup} from "../wc/aPopupGroup.js";

customElements.define('a-popup', aPopup);


const template = document.createElement('template');
template.innerHTML = `
  <style>
    #login {
      display: block;
    }
    #logout {
      display: none;
    }
    :host {
      display: block;
      border: 2px solid orangered;
    }
    :host([active]) > #login {
      display: none;
    }
    :host([active]) > #logout {
      display: block;
    }
  </style>
  <div id="login">
    <h3>login</h3>
    RememberMe: <input type='checkbox'/><br>
    <a-popup href="https://auth.2js.no/login/google" group="login">login google</a-popup><br>
    <a-popup href="https://auth.2js.no/login/github" group="login">login github</a-popup><br>
  </div>
  <div id="logout">
    <pre></pre>
    <!--todo should logout occur in the main window?-->
    <a-popup href="https://auth.2js.no/logout">logout</a-popup><br>
    <a-popup href="https://db.2js.no/SESSION">see the data stored in a cookie on my computer</a-popup>
  </div>
`;

export class UserData extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode: "open"});
    this.shadowRoot.append(template.content.cloneNode(true));
  }

  setUserData(data) {
    this.shadowRoot.querySelector('pre').innerText = data;
    data ? this.setAttribute('active', 'loggedIn') : this.removeAttribute('active');
  }
}