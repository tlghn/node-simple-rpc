# node-simple-rpc
Simple RPC server and client for Node.js

### Install
```
    npm i node-simple-rpc --save
```

### Usage

Options : 
```
    var options = {
        // Server host or ip address
        host: 'localhost',
        // Server port
        port: 12345,
        // Auth key, optional
        auth: 'Your auth key',
        // Max RPC Request length, defaults to 1MB.
        // Used by server only
        maxUploadSize: 1048576
    };
```


Server : 
```
    const rpcServer = require('node-simple-rpc').server(options);
    
    rpcServer.exports = {
        helloWorld: (name, req, next) => {
            next(null, "Hello " + name + "!");
        },
        
        add: (a, b, req, next) => {
            next(null, a + b);
        },
        
        throwIfArgLte5: (arg, req, next) => {
            if(arg <= 5) {
                return next(new Error(arg + " <= 5"));
            }
            next(null, "Yo!");
        },
        
        // demonstrate multiple args
        createFullName: (name, surname, next) => {
            next(null, name, surname, name + ' ' + surname);
        }
    };
```


Client : 
```
    const rpcClient = require('node-simple-rpc').client(options);
    
    rpcClient.helloWorld("John Doe", (err, result, req) => {
        console.log(result);
        // output : Hello John Doe!
    });
    
    rpcClient.add(1, 2, (err, result, req) => {
        var args = req.input.data.args;
        console.log("%s + %s = %s", args[0], args[1], result);
        // output : 1 + 2 = 3
    });
    
    // Below call will output: "Error : 4 <= 5"
    rpcClient.throwIfArgLte5(4, (err, result, req) => {
        if(err){
            return console.log("Error : %s", err.message);
        }
        console.log(result);
    });
    
    // Below call will output: "Yo!"
    rpcClient.throwIfArgLte5(6, (err, result, req) => {
        if(err){
            return console.log("Error : %s", err.message);
        }
        console.log(result);
    });
    
    rpcClient.createFullName("John", "Doe", (err, name, surname, fullName, req) => {
        console.log(fullName);
        // output: John Doe
    });
```

Server Middleware : 
```
    const rpcServer = require('node-simple-rpc').server(options);

    rpcServer.use((req, next) => {
        
        if(req.auth !== "Your auth key") {
            return next(new Error("Unauthorized"));
        }
        
        next();
    });

```
