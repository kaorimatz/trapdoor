import 'xterm/dist/xterm.css';
import * as fit from 'xterm/lib/addons/fit/fit';
import * as xterm from 'xterm';
import LocalEchoController from 'local-echo';
import * as base64ArrayBuffer from 'base64-arraybuffer';

xterm.Terminal.applyAddon(fit);

const inputMessage  = String.fromCharCode(1);
const resizeMessage = String.fromCharCode(2);
const tokenMessage  = String.fromCharCode(3);

const outputMessage      = 1;
const windowTitleMessage = 2;
const tokenExpiryMessage = 3;

const fontFamily = 'SFMono-Regular,Consolas,Menlo,monospace'
const colorPalette = {
  black:       '#1c1c1c',
  brightBlack: '#373c38',
  red:         '#eb7a77',
  green:       '#90b44b',
  yellow:      '#e2943b',
  blue:        '#58b2dc',
  magenta:     '#b28fce',
  cyan:        '#6699a1',
  white:       '#828282',
  brightWhite: '#bdc0ba',
};
const theme = {
  foreground:    colorPalette.brightWhite,
  background:    colorPalette.black,
  cursor:        colorPalette.white,
  cursorAccent:  colorPalette.brightWhite,
  selection:     colorPalette.brightWhite + '7f',
  black:         colorPalette.black,
  red:           colorPalette.red,
  green:         colorPalette.green,
  yellow:        colorPalette.yellow,
  blue:          colorPalette.blue,
  magenta:       colorPalette.magenta,
  cyan:          colorPalette.cyan,
  white:         colorPalette.white,
  brightBlack:   colorPalette.brightBlack,
  brightRed:     colorPalette.red,
  brightGreen:   colorPalette.green,
  brightYellow:  colorPalette.yellow,
  brightBlue:    colorPalette.blue,
  brightMagenta: colorPalette.magenta,
  brightCyan:    colorPalette.cyan,
  brightWhite:   colorPalette.brightWhite,
};

class HTTPError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
  }
}

class Connection {
  constructor(target, token, csrfToken, callback) {
    this.target = target;
    this.token = token;
    this.csrfToken = csrfToken;
    this.callback = callback;
    this.dataListener = (data) => { this.sendInputMessage(data) };
    this.resizeListener = (data) => { this.sendResizeMessage(data.rows, data.cols) };
    this.messageListener = (event) => { this.onMessage(event.data) };
    this.utf8Decoder = new TextDecoder();
  }

  sendInputMessage(data) {
    this.ws.send(inputMessage + data);
  }

  sendResizeMessage(rows, cols) {
    this.ws.send(resizeMessage + JSON.stringify([rows, cols]));
  }

  onMessage(message) {
    const messageType = message.codePointAt(0)
    const payload = message.slice(1);
    switch (messageType) {
      case outputMessage:
        const output = this.utf8Decoder.decode(base64ArrayBuffer.decode(payload), { stream: true });
        this.term.write(output);
        break;
      case windowTitleMessage:
        document.title = payload;
        break;
      case tokenExpiryMessage:
        this.createToken().then(token => this.sendToken(token.token));
        break;
      default:
        console.log(`unknown message type: ${messageType}`);
    }
  }

  createToken() {
    return fetch(this.target.tokensUrl, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': this.csrfToken,
      },
      credentials: 'same-origin',
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        return Promise.reject(new HTTPError('Failed to create a token', response.status));
      }
    });
  }

  attach(term) {
    this.term = term;
    this.ws = new WebSocket(this.target.proxy.endpoint);
    this.ws.onopen = (event) => {
      this.sendToken(this.token);
      this.sendResizeMessage(this.term.rows, this.term.cols);
      this.term.on('data', this.dataListener);
      this.term.on('resize', this.resizeListener);
      this.ws.addEventListener('message', this.messageListener);
    };
    this.ws.onclose = (event) => {
      this.term.write(`\u001B[37mConnection to ${this.target.name} closed.\u001B[0m\r\n`);
      this.callback();
    };
    this.ws.onerror = (event) => {
      this.term.write(`\u001B[31m${error}\u001B[0m\r\n`);
    };
  }

  sendToken(token) {
    this.ws.send(tokenMessage + token);
  }

  detach(term) {
    this.ws.removeEventListener('message', this.messageListener);
    this.term.off('resize', this.resizeListener);
    this.term.off('data', this.dataListener);
    this.ws.close();
    this.ws = null;
    this.term = null;
  }
}

class TargetSelector {
  constructor(csrfToken, callback) {
    this.csrfToken = csrfToken;
    this.callback = callback;
  }

  attach(term) {
    this.localEcho = new LocalEchoController(term);
    this.listTargets()
      .then(targets => {
        return this.selectTarget(this.sortTargetsByName(targets));
      }).then(target => {
        return this.createToken(target).then(token => {
          this.callback(target, token.token);
        });
      }).catch(error => {
        if (error instanceof HTTPError && error.statusCode == 401) {
          this.localEcho.println(`\u001B[31mPlease sign in again by reloading the page.\u001B[0m`);
        } else {
          this.localEcho.println(`\u001B[31m${error}\u001B[0m`);
        }
      });
  }

  listTargets() {
    return fetch('/api/targets', {
      credentials: 'same-origin',
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        return Promise.reject(new HTTPError('Failed to get targets', response.status));
      }
    });
  }

  sortTargetsByName(targets) {
    return targets.slice().sort((t1, t2) => t1.name.localeCompare(t2.name));
  }

  selectTarget(targets) {
    targets.forEach((target, i) => {
      this.localEcho.println(`${i + 1}) ${target.name}`);
    });
    return this.localEcho.read('> ').then(input => {
      const i = parseInt(input, 10)
      if (!isNaN(i) && i - 1 < targets.length) {
        return targets[i - 1];
      }
      const target = targets.find(t => t.name == input);
      if (target !== undefined) {
        return target;
      }
      return this.selectTarget(targets);
    });
  }

  createToken(target) {
    return fetch(target.tokensUrl, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': this.csrfToken,
      },
      credentials: 'same-origin',
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        return Promise.reject(new HTTPError('Failed to create a token', response.status));
      }
    });
  }

  detach(term) {
    // XXX: Remove listeners registered by LocalEchoController
    term._core.removeAllListeners('data');
    term._core.listeners('resize').pop();
  }
}

class Terminal {
  constructor(element, csrfToken) {
    this.element = element;
    this.csrfToken = csrfToken;
    this.windowResizeListener = () => { this.term.fit() };
  }

  open() {
    this.openTerminal();
    this.selectTarget();
  }

  selectTarget() {
    const selector = new TargetSelector(this.csrfToken, (target, token) => {
      this.connectToTarget(target, token);
    });
    this.attachBackend(selector);
  }

  attachBackend(backend) {
    if (this.backend) {
      this.backend.detach(this.term);
    }
    this.backend = backend;
    if (this.backend) {
      this.backend.attach(this.term);
    }
  }

  connectToTarget(target, token) {
    const connection = new Connection(target, token, this.csrfToken, this.selectTarget.bind(this));
    this.attachBackend(connection);
  }

  openTerminal() {
    this.term = new xterm.Terminal({
      fontFamily: fontFamily,
      theme: theme,
    });
    this.term.open(this.element);
    this.term.fit();
    this.term.focus();
    window.addEventListener('resize', this.windowResizeListener);
  }

  dispose() {
    this.attachBackend(null);
    this.closeTerminal();
  }

  closeTerminal() {
    if (this.term) {
      window.removeEventListener('resize', this.windowResizeListener);
      this.term.dispose();
      this.term = null;
    }
  }
}

export default Terminal
