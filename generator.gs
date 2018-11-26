var AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'; //'';
var AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; //'';
var REGION = 'eu-west-2';
var EXPIRES = 3600;//in seconds

//  var now = new Date(Date.UTC(2013, 5-1, 24, 0, 0,0));

/**
 * Raises a number to the given power, and returns the result.
 *
 * @param {string} bucket the number we're raising to a power
 * @param {string} path the exponent we're raising the base to
 * @return {string} the result of the exponential calculation
 */
function generateS3Url(bucket, path) {

    var timestamp = Date.now();

    var url = generateS3GetUrlGivenAllParams(
        AWS_KEY,
        AWS_SECRET,
        REGION,
        bucket,
        path,
        timestamp,
        EXPIRES
    );

    return url;
}

function generateS3GetUrlGivenAllParams(
    aws_key,
    aws_secret,
    region,
    bucket,
    path,
    timestamp,
    expires
) {

    var datetime = new Date(timestamp);

    var canonicalRequest = buildCanonicalRequest(aws_key, bucket, path, datetime, region, expires);
    var stringToSign = buildStringToSign(canonicalRequest, region, datetime);
    var signingKey = computeSigningKey(aws_secret, datetime, region);
    var signature = computeSignature(signingKey, stringToSign);
    var amzDate = dateInto8601(datetime);
    var amzCredential = getAmzCredential(aws_key, datetime, region);

    var presignedURL = 'https://' + bucket + '.s3.amazonaws.com/' + encodeURIComponent(path)  +
        '?X-Amz-Algorithm=AWS4-HMAC-SHA256' +
        '&X-Amz-Credential=' + amzCredential +
        '&X-Amz-Date=' + amzDate +
        '&X-Amz-Expires=' + expires +
        '&X-Amz-SignedHeaders=host' +
        '&X-Amz-Signature=' + signature;

    return presignedURL;
}

function buildCanonicalRequest(aws_key, bucket, path, datetime, region, expires) {

    var amzCredential = getAmzCredential(aws_key, datetime, region);
    var amzDate = dateInto8601(datetime);
    var host = bucket + '.s3.amazonaws.com';

    var requestFormat = 'GET\n'+
        '/%s\n'+
        'X-Amz-Algorithm=AWS4-HMAC-SHA256&'+
        'X-Amz-Credential=%s&'+
        'X-Amz-Date=%s&'+
        'X-Amz-Expires=%s&'+
        'X-Amz-SignedHeaders=host\n'+
        'host:%s\n\n'+
        'host\n'+
        'UNSIGNED-PAYLOAD';

    var request = Utilities.formatString(
        requestFormat,
        path,
        amzCredential,
        amzDate,
        expires,
        host
    );

    return request;
}

function getAmzCredential(aws_key, datetime, region) {
    var date = Utilities.formatDate(datetime,'GMT', 'yyyyMMdd');
    var format =  '%s/%s/%s/s3/aws4_request';
    var raw = Utilities.formatString(format, aws_key, date, region);
    var uri_encoded = encodeURIComponent(raw);
    return uri_encoded;
}

function dateInto8601(datetime) {
    var amzDate = Utilities.formatDate(datetime,'GMT', 'yyyyMMdd\'T\'HHmmss\'Z\'');
    return amzDate;
}

function buildStringToSign(canonicalRequest, region, datetime) {

    var date = Utilities.formatDate(datetime, 'GMT', 'yyyyMMdd');
    var scope = Utilities.formatString('%s/%s/s3/aws4_request', date, region);

    var timestamp = dateInto8601(datetime);
    var hash = getSha256Hash(canonicalRequest);
    var hexHash = intoHex(hash);

    var stringFormat = 'AWS4-HMAC-SHA256\n%s\n%s\n%s';
    var stringToSign = Utilities.formatString(stringFormat, timestamp, scope, hexHash);
    return stringToSign;
}

function getSha256Hash(value) {

    var hash = Utilities.computeDigest(
        Utilities.DigestAlgorithm.SHA_256,
        value,
        Utilities.Charset.UTF_8
    );

    return hash;
}

function intoHex(value) {
    //inspired by https://stackoverflow.com/a/41232906

    return value.reduce(function(str,chr) {
        chr = (chr < 0 ? chr + 256 : chr).toString(16);
        return str + (chr.length==1?'0':'') + chr;
    },'');
}

function computeSigningKey(aws_secret, datetime, region) {

    var date =  Utilities.formatDate(datetime,'GMT', 'yyyyMMdd');
    var dateKey = getHmacSha256('AWS4' + aws_secret, date);
    var dateRegionKey = getHmacSha256(dateKey,region);
    var dateRegionServiceKey = getHmacSha256(dateRegionKey,"s3");
    var signingKey = getHmacSha256(dateRegionServiceKey,"aws4_request");
    return signingKey;
}

function getHmacSha256(key, value) {

    //this is how Google Apps Script needs to have it
    //see
    var value_prepared = Utilities.base64Decode(Utilities.base64Encode(value));
    var key_prepared = Utilities.base64Decode(Utilities.base64Encode(key));

    var hmac = Utilities.computeHmacSha256Signature(
        value_prepared,
        key_prepared
    );

    return hmac;
}

function computeSignature(key, string) {
    var hmac = getHmacSha256(key, string);
    var hex = intoHex(hmac);
    return hex;
}
