// Runtime confirmation of static findings: log every cipher transform and
// digest algorithm the app actually asks for.
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (transform) {
        send({ type: 'cipher', transform: transform });
        return this.getInstance(transform);
    };

    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
        send({ type: 'digest', algorithm: algo });
        return this.getInstance(algo);
    };
});
