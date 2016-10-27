/**
 * Created by tolgahan on 27.10.2016.
 */
const util = require('util');

class RPCError extends Error {
    constructor(){
        super();
    }

    init(){
        var args = Array.prototype.slice.call(arguments, 0);
        var props;
        var message;

        if(args.length){
            if(typeof args[args.length - 1] === 'object'){
                props = args.pop();
            }
        }

        if(args.length){
            message = util.format.apply(null, args);
        }

        this.message = message;

        if(props){
            Object.assign(this, props);
        }

        this.name = this.constructor.name;

        Error.captureStackTrace && Error.captureStackTrace(this);

    }
}

function createError(name) {
    return eval('(class ' + name + ' extends RPCError { constructor(){ super(); this.init.apply(this, arguments); } })');
}

module.exports = {
    RPCError,
    MethodNotFoundError: createError('MethodNotFoundError'),
    AuthenticationError: createError('AuthenticationError'),
    UnsupportedTypeError: createError('UnsupportedTypeError'),
    EndOfStreamError: createError('EndOfStreamError'),
    UnexpectedValueError: createError('UnexpectedValueError'),
    InputOutOfRangeError: createError('InputOutOfRangeError'),
    InvalidRequestError: createError('InvalidRequestError'),
    UnhandledError: createError('UnhandledError')
};