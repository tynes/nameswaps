/**
 *
 */

const assert = require('bsert');

const common = exports;

common.event = async function event(obj, name) {
  return new Promise((resolve) => {
    obj.once(name, resolve);
  });
};

common.forValue = async function(obj, key, val, timeout = 30000) {
  assert(typeof obj === 'object');
  if (typeof key === 'number')
    key = key.toString();
  assert(typeof key === 'string');

  const ms = 10;
  let interval = null;
  let count = 0;

  return new Promise((resolve, reject) => {
    interval = setInterval(() => {
      let res = val;
      if (typeof res === 'function')
        res = res();

      if (obj[key] === res) {
        clearInterval(interval);
        resolve();
      } else if (count * ms >= timeout) {
        clearInterval(interval);
        reject(new Error('Timeout waiting for value.'));
      }
      count += 1;
    }, ms);
  });
};

common.forCallback = async function(cb, timeout = 30000) {
  assert(typeof cb === 'function')

  const ms = 10;
  let interval = null;
  let count = 0;

  return new Promise((resolve, reject) => {
    interval = setInterval(() => {
      let res = cb();
      if (res) {
        clearInterval(interval);
        resolve();
      } else if (count * ms >= timeout) {
        clearInterval(interval);
        reject(new Error('Timeout waiting for value.'));
      }
      count += 1;
    }, ms);
  });
};

