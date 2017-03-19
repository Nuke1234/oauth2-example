let request = require("request");
let server = require("../server.js");
let base_url = "http://localhost:7000/";

describe("when registering a system", function(){
    it("should return status OK", function(done){

        let options = {
            uri: base_url+"register",
            method: 'POST',
            json:{"name": "System 1", "redirect_uri": "https://www.google.at"}
        };

        request(options, function(error, response, body) {
            expect(response.statusCode).toBe(201);
            expect(body).toBeNull(body);
            done();
        });
    });
});