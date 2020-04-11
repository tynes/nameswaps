/**
 *
 */

'use strict';

const assert = require('bsert');
const Script = require('hsd/lib/script/script');
const Opcode = require('hsd/lib/script/opcode');
const common = require('hsd/lib/script/common');
const rules = require('hsd/lib/covenants/rules');

const SINGLEREVERSE = common.hashType.SINGLEREVERSE;
const ANYONECANPAY = common.hashType.ANYONECANPAY;

const types = {
  NAIVE: 0
};

const typesByVal = {
  [types.NAIVE]: 'NAIVE'
};

const templatesByType = {
  [types.NAIVE]: naive
};

const flagsByType = {
  [types.NAIVE]: ANYONECANPAY | SINGLEREVERSE
};

class Scripts {
  constructor() {
    this.type = -1;
    this.template = () => new Script();
    this.script = new Script();
  }

  fill(data) {
    this.script = this.template(data);
  }

  compile() {
    this.script.compile();
  }

  getScript() {
    this.script.compile();
    return this.script;
  }

  fromType(type, data) {
    assert(typeof type === 'number');
    assert(type in typesByVal, 'Invalid script type');

    this.type = type;
    this.template = templatesByType[type];

    if (data)
      this.script = this.template(data);

    return this;
  }

  fromOptions(options) {
    assert(typeof options.type === 'number');
    assert(options.script instanceof Script);
    assert(typeof options.template === 'function');

    this.type = options.type;
    this.script = options.script;
    this.template = options.template;

    return this;
  }

  // TODO
  fromJSON(json) {
    return this;
  }

  static fromType(type, data) {
    return new this().fromType(type, data);
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

// templates are a function that returns a script
function naive(pubkey) {
  // for some reason
  return new Script([
    Opcode.fromSymbol('type'),
    Opcode.fromInt(rules.types.UPDATE),
    Opcode.fromSymbol('equal'),
    Opcode.fromSymbol('if'),
    Opcode.fromSymbol('return'),
    Opcode.fromSymbol('endif'),

    Opcode.fromSymbol('type'),
    Opcode.fromInt(rules.types.REVOKE),
    Opcode.fromSymbol('equal'),
    Opcode.fromSymbol('if'),
    Opcode.fromSymbol('return'),
    Opcode.fromSymbol('endif'),

    Opcode.fromSymbol('type'),
    Opcode.fromInt(rules.types.RENEW),
    Opcode.fromSymbol('equal'),
    Opcode.fromSymbol('if'),
    Opcode.fromSymbol('return'),
    Opcode.fromSymbol('endif'),

    Opcode.fromSymbol('type'),
    Opcode.fromInt(rules.types.TRANSFER),
    Opcode.fromSymbol('equal'),
    Opcode.fromSymbol('if'),
    Opcode.fromPush(pubkey),
    Opcode.fromSymbol('checksigverify'),
    Opcode.fromSymbol('endif'),

    // fromSymbol('true')
    Opcode.fromInt(1)
  ]);
};

Scripts.types = types;
Scripts.typesByVal = typesByVal;
Scripts.templatesByType = templatesByType;
Scripts.flagsByType = flagsByType;

module.exports = Scripts;
