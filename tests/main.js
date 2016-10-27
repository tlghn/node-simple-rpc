/**
 * Created by tolgahan on 27.10.2016.
 */
const net = require('net');
const chai = require('chai');
const expect = chai.expect;
const should = chai.should();
const assert = chai.assert;
const options = require('./options');
const rpc = require('../');

describe('Instantinate', function () {

    describe('Server', function () {

        describe('with options', function () {
            it('Server.host property should return the host value in passed options', function () {
                var server = rpc.server(options);
                expect(server.host).to.equal(options.host);
            });

            it('Server.port property should return the port value in passed options', function () {
                var server = rpc.server(options);
                expect(server.port).to.equal(options.port);
            });

            it('Server.auth property should return the auth value in passed options', function () {
                var server = rpc.server(options);
                expect(server.auth).to.equal(options.auth);
            });

            it('Server.maxUploadSize property should return the maxUploadSize value in passed options', function () {
                var server = rpc.server(options);
                expect(server.maxUploadSize).to.equal(options.maxUploadSize);
            });
        });

        describe('with net.Server and options', function () {
            it('Server.host property should equal Server.address().address property in passed arg', function (done) {
                var netServer = net.createServer();
                netServer.listen(0, '0.0.0.0');
                netServer.on('listening', function () {
                    var server = rpc.server(netServer, options);
                    expect(server.host).to.equal(netServer.address().address);
                    server.stop();
                    done();
                });
            });

            it('Server.port property should equal Server.address().port property in passed arg', function (done) {
                var netServer = net.createServer();
                netServer.listen(0, '0.0.0.0');
                netServer.on('listening', function () {
                    var server = rpc.server(netServer, options);
                    expect(server.port).to.equal(netServer.address().port);
                    server.stop();
                    done();
                });
            });


            it('Server.auth property should return the auth value in passed options', function () {
                var netServer = net.createServer();
                var server = rpc.server(netServer, options);
                expect(server.auth).to.equal(options.auth);
            });

            it('Server.maxUploadSize property should return the maxUploadSize value in passed options', function () {
                var netServer = net.createServer();
                var server = rpc.server(netServer, options);
                expect(server.maxUploadSize).to.equal(options.maxUploadSize);
            });
        });

    });

    describe('Client', function () {

        describe('with options', function () {
            it('Client.host property should return the host value in passed options', function () {
                var client = rpc.client(options);
                expect(client.host).to.equal(options.host);
            });

            it('Client.port property should return the port value in passed options', function () {
                var client = rpc.client(options);
                expect(client.port).to.equal(options.port);
            });

            it('Client.auth property should return the auth value in passed options', function () {
                var client = rpc.client(options);
                expect(client.auth).to.equal(options.auth);
            });

        });

    });

});

describe('Communication', function () {

    var server, client;
    var errors = rpc.errors;

    before(function () {
        server = rpc.server(options);
        client = rpc.client(options);

        server.exports = {

            echo: function (msg, req, next) {
                next(null, msg);
            },

            add: function (a, b, req, next) {
                next(null, a + b);
            },

            throwError: function (message, req, next) {
                throw new Error(message);
            }
        };

        server.start();
    });

    describe('Errors', function () {

        it('Should throw MethodNotFoundError', function (done) {
            client.notDefinedMethod(function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.MethodNotFoundError);
                done();
            });
        });

        it('Should throw InputOutOfRangeError', function (done) {
            server.options.maxUploadSize = 10;
            client.add(1, 2, function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.InputOutOfRangeError);
                server.options.maxUploadSize = options.maxUploadSize;
                done();
            });
        });

        it('Should throw AuthenticationError', function (done) {
            client.auth = 'wrong auth';
            client.add(1, 2, function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.AuthenticationError);
                client.auth = options.auth;
                done();
            });
        });

        it('Should throw InvalidRequestError', function (done) {
            client.add(1, 2, 3, function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.InvalidRequestError);
                done();
            });
        });

        it('Should throw UnhandledError', function (done) {
            client.throwError("some error message", function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.UnhandledError);
                done();
            });
        });

        it('Should throw UnsupportedTypeError', function (done) {
            client.add(Symbol("1"), 2, function (err) {
                should.exist(err);
                assert.instanceOf(err, errors.UnsupportedTypeError);
                done();
            });
        });
    });

    describe('Request & Response', function () {

        it('Call method', function (done) {
            client.echo("test", function (err, result) {
                should.not.exist(err);
                expect(result).to.equal("test");
                done();
            });
        });

        it('Use request parameters on complete callback', function (done) {
            client.add(1, 2, function (err, result, req) {
                expect(req.input.data.args).to.eql([1, 2]);
                done();
            });
        });

        it('Do multiple calls', function (done) {
            var count = 10;
            for(var i=0; i<count; i++){
                client.echo("call:" + i, function (err, result, req) {
                    should.not.exist(err);
                    var arg = req.input.data.args[0];
                    expect(result).to.equal(arg);
                    if(!--count){
                        done();
                    }
                });
            }
        });

    });


    after(function () {
        server.stop();
    });

});