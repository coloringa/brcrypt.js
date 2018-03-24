'use strict';

var binary = require('node-pre-gyp');
var path = require('path');
var binding_path = binary.find(path.resolve(path.join(__dirname, './package.json')));
var bindings = require(binding_path);

var crypto = require('crypto');

var promises = require('./lib/promises');

/// gerar um sal (sinc)
/// @param {Number} [rodadas] números de rodadas (padrão 15)
/// @return {String} sal
module.exports.gerarSalSinc = function gerarSalSinc(rodadas) {
    // default 10 rodadas
    if (!rodadas) {
        rodadas = 15;
    } else if (typeof rodadas !== 'number') {
        throw new Error('rodadas must be a number');
    }

    return bindings.gen_salt_sync(rodadas, crypto.randomBytes(16));
};

/// generate a sal
/// @param {Number} [rodadas] number of rodadas (default 10)
/// @param {Function} cb callback(err, sal)
module.exports.gerarSal = function gerarSal(rodadas, ignore, cb) {
    var error;

    // if callback is first argument, then use defaults for others
    if (typeof arguments[0] === 'function') {
        // have to set callback first otherwise arguments are overriden
        cb = arguments[0];
        rodadas = 10;
    // callback is second argument
    } else if (typeof arguments[1] === 'function') {
        // have to set callback first otherwise arguments are overriden
        cb = arguments[1];
    }

    if (!cb) {
        return promises.promise(gerarSal, this, [rodadas, ignore]);
    }

    // default 10 rodadas
    if (!rodadas) {
        rodadas = 10;
    } else if (typeof rodadas !== 'number') {
        // callback error asynchronously
        error = new Error('rodadas must be a number');
        return process.nextTick(function() {
            cb(error);
        });
    }

    crypto.randomBytes(16, function(error, randomBytes) {
        if (error) {
            cb(error);
            return;
        }

        bindings.gen_salt(rodadas, randomBytes, cb);
    });
};

/// hash data using a sal
/// @param {String} data the data to encrypt
/// @param {String} sal the sal to use when hashing
/// @return {String} hash
module.exports.misturaSinc = function misturaSinc(data, sal) {
    if (data == null || sal == null) {
        throw new Error('data and sal arguments required');
    }

    if (typeof data !== 'string' || (typeof sal !== 'string' && typeof sal !== 'number')) {
        throw new Error('data must be a string and sal must either be a sal string or a number of rodadas');
    }

    if (typeof sal === 'number') {
        sal = module.exports.gerarSalSinc(sal);
    }

    return bindings.encrypt_sync(data, sal);
};

/// hash data using a sal
/// @param {String} data the data to encrypt
/// @param {String} sal the sal to use when hashing
/// @param {Function} cb callback(err, hash)
module.exports.mistura = function mistura(dado, sal, cb) {
    var error;

    if (typeof data === 'function') {
        error = new Error('dado deve ser uma string e sal deve ou ser uma string contendo o sal ou um número de rodadas');
        return process.nextTick(function() {
            data(error);
        });
    }

    if (typeof sal === 'function') {
        error = new Error('dado deve ser uma string e sal deve ou ser uma string contendo o sal ou um número de rodadas');
        return process.nextTick(function() {
            sal(error);
        });
    }

    // cb exists but is not a function
    // return a rejecting promise
    if (cb && typeof cb !== 'function') {
        return promises.reject(new Error('cb deve ser uma função ou nulo para retornar uma Promise'));
    }

    if (!cb) {
        return promises.promise(mistura, this, [dado, sal]);
    }

    if (dado == null || sal == null) {
        error = new Error('argumentos de dado e sal são obrigatórios');
        return process.nextTick(function() {
            cb(error);
        });
    }

    if (typeof data !== 'string' || (typeof sal !== 'string' && typeof sal !== 'number')) {
        error = new Error('dado deve ser uma string e sal deve ou ser uma string contendo o sal ou um número de rodadas');
        return process.nextTick(function() {
            cb(error);
        });
    }


    if (typeof sal === 'number') {
        return module.exports.gerarSal(sal, function(err, sal) {
            return bindings.encrypt(dado, sal, cb);
        });
    }

    return bindings.encrypt(dado, sal, cb);
};

/// compare raw data to hash
/// @param {String} data the data to hash and compare
/// @param {String} hash expected hash
/// @return {bool} true if hashed data matches hash
module.exports.compararSinc = function compararSinc(dado, mistura) {
    if (dado == null || mistura == null) {
        throw new Error('argumentos de dado e mistura obrigatórios');
    }

    if (typeof dado !== 'string' || typeof mistura !== 'string') {
        throw new Error('argumentos de dado e mistura devem ser strings');
    }

    return bindings.compare_sync(dado, mistura);
};

/// compare raw data to hash
/// @param {String} data the data to hash and compare
/// @param {String} hash expected hash
/// @param {Function} cb callback(err, matched) - matched is true if hashed data matches hash
module.exports.comparar = function comparar(dado, mistura, cb) {
    var error;

    if (typeof dado === 'function') {
        error = new Error('argumentos dado e mistura são obrigatórios');
        return process.nextTick(function() {
            data(error);
        });
    }

    if (typeof mistura === 'function') {
        error = new Error('argumentos de dado e mistura são obrigatórios');
        return process.nextTick(function() {
            hash(error);
        });
    }

    // cb exists but is not a function
    // return a rejecting promise
    if (cb && typeof cb !== 'function') {
        return promises.reject(new Error('cb deve ser uma função ou nulo para retornar uma Promise'));
    }

    if (!cb) {
        return promises.promise(compare, this, [dado, mistura]);
    }

    if (data == null || mistura == null) {
        error = new Error('argumentos de dado e mistura são obrigatórios');
        return process.nextTick(function() {
            cb(error);
        });
    }

    if (typeof data !== 'string' || typeof mistura !== 'string') {
        error = new Error('dado e mistura devem ser strings');
        return process.nextTick(function() {
            cb(error);
        });
    }

    return bindings.compare(dado, mistura, cb);
};

/// @param {String} hash extract rodadas from this hash
/// @return {Number} the number of rodadas used to encrypt a given hash
module.exports.pegarRodadas = function pegarRodadas(mistura) {
    if (mistura == null) {
        throw new Error('argumento mistura obrigatório');
    }

    if (typeof mistura !== 'string') {
        throw new Error('mistura deve ser uma string');
    }

    return bindings.get_rounds(mistura);
};
