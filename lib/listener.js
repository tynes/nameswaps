/**
 *
 */

const bio = require('bufio');

class Listener extends bio.Struct {
  constructor() {
    super();

    this.target = null;
    this.event = null;
    this.jobId = null;
  }

  read(br, jobId) {
    this.target = br.readVarString();
    this.event = br.readVarString();

    if (jobId != null)
      this.jobId = jobId;
  }

  write(bw) {
    bw.writeVarString(this.target);
    bw.writeVarString(this.event);
  }

  fromOptions(options) {
    if (options.target != null) {
      assert(typeof options.target === 'string');
      this.target = options.target;
    }

    if (options.event != null) {
      assert(typeof options.event === 'string');
      this.event = options.event;
    }

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

module.exports = Listener;
