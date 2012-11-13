package com.northridgerochester;

import org.apache.commons.codec.binary.*;
import org.apache.log4j.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;

/**
 * Created by IntelliJ IDEA.
 * User: lloydmurray
 * Date: Sep 30, 2012
 * Time: 4:20:14 PM
 */
public class OAuthUtil {

    private static String CHARSET = "UTF-8";

    public static Logger logger = Logger.getLogger(OAuthUtil.class);


    private String _consumerKey = "";

    public String getConsumerKey() {
        return this._consumerKey;
    }

    private String _consumerSecret = "";

    public String getConsumerSecret() {
        return _consumerSecret;
    }

    private String _baseAPIUrl = "";

    protected String getBaseAPIUrl() {
        return _baseAPIUrl;
    }

    private String _apiVersion = "";

    protected String getApiVersion() {
        return _apiVersion;
    }

    private String _churchCode = "";

    protected String getChurchCode() {
        return _churchCode;
    }

    private String _requestUrl = "";

    protected String getRequestUrl() {
        return _requestUrl;
    }

    private String _userAuthorizeUrl = "";

    protected String getUserAuthorizeUrl() {
        return _userAuthorizeUrl;
    }

    private String _trustedUrl = "";

    protected String getTrustedUrl() {
        return _trustedUrl;
    }

    private String _accessUrl = "";

    protected String getAccessUrl() {
        return _accessUrl;
    }

    public OAuthUtil(String baseAPIUrl, String churchCode, String apiVersion, String f1LoginMethod,
                     String consumerKey, String consumerSecret) {
        _baseAPIUrl = baseAPIUrl;
        _apiVersion = apiVersion;
        _churchCode = churchCode;
        _requestUrl = createAPIUrl(churchCode, baseAPIUrl, apiVersion, "Tokens/RequestToken");
        _userAuthorizeUrl = createAPIUrl(churchCode, baseAPIUrl, apiVersion, f1LoginMethod + "/Login");
        _accessUrl = createAPIUrl(churchCode, baseAPIUrl, apiVersion, "Token/AccessToken");
        _trustedUrl = createAPIUrl(churchCode, baseAPIUrl, apiVersion, f1LoginMethod + "/AccessToken");
        _consumerKey = consumerKey;
        _consumerSecret = consumerSecret;

        logger.info("requestUrl=" + _requestUrl);
        logger.info("userAuthorizeUrl=" + _userAuthorizeUrl);
        logger.info("accessUrl=" + _accessUrl);
        logger.info("trustedUrl=" + _trustedUrl);

    }

    private static String OAuthVersion = "1.0";
    private static String OAuthParameterPrefix = "oauth_";

    //
    // List of known and used oauth parameters' names
    //
    private static String OAuthConsumerKeyKey = "oauth_consumer_key";
    private static String OAuthCallbackKey = "oauth_callback";
    private static String OAuthVersionKey = "oauth_version";
    private static String OAuthSignatureMethodKey = "oauth_signature_method";
    private static String OAuthSignatureKey = "oauth_signature";
    private static String OAuthTimestampKey = "oauth_timestamp";
    private static String OAuthNonceKey = "oauth_nonce";
    private static String OAuthTokenKey = "oauth_token";
    private static String OAuthTokenSecretKey = "oauth_token_secret";

    private static String HMACSHA1SignatureType = "HMAC-SHA1";

    private static final String HMAC_SHA1 = "HmacSHA1";

    /// <summary>
    /// Creates a full url for the api. (e.g. "https://mychurchcode.staging.fellowshiponeapi.com/v1/WeblinkUser/Login")
    /// </summary>
    /// <param name="baseAPIUrl"></param>
    /// <param name="apiVersion"></param>
    /// <param name="url"></param>
    /// <returns></returns>

    public String createAPIUrl(String churchCode, String baseAPIUrl, String apiVersion, String partialUrl) {
        return "https://" + churchCode + "." + baseAPIUrl + "/" + apiVersion + "/" + partialUrl;
    }

    /*
		/// <summary>
		/// Step #1:  Get an Unauthenticated request token
		/// </summary>
		/// <returns></returns>
		public Token getRequestToken() throws MalformedURLException {
			Token requestToken = null;
			URL url = new URL(getRequestUrl());
			String nonce = generateNonce();
			String timestamp = GenerateTimeStamp();
			String normalizedUrl = "";
			String normalizedReqParms = "";
			String signatureBase = "";
			// First we generate a signature String. This incorporates multi-layered security goodness to make sure the url we're about to send cannot be used by anyone else,
			//  cannot be used more than once, and cannot be used outside of a specific time period.
			String sig = GenerateSignature(url, getConsumerKey(), getConsumerSecret(), null, null, "GET", timestamp, nonce, out normalizedUrl, out normalizedReqParms, out signatureBase);
			
			try {
				HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url);
				// Everything gets stamped into a header (including the url)
				String authHeader = buildOAuthHeader(ConsumerKey, nonce, sig, "HMAC-SHA1", timestamp, "");
				request.Headers.Add("Authorization", authHeader);
				request.ContentType = "appliation/json";
				request.Method = "GET";

				// Execute the webRequest
				WebResponse webResponse = request.GetResponse();
				StreamReader sr = new StreamReader(webResponse.GetResponseStream());
				// Read the response into a String
				String results = sr.ReadToEnd().Trim();

				// Parse out the request token
				String[] tokeninfo = results.Split('&');
				requestToken = new Token();
				requestToken.Value = tokeninfo[0].Replace("oauth_token=", "");
				requestToken.Secret = tokeninfo[1].Replace("oauth_token_secret=", "");
			}
			catch (WebException we) {
                HttpWebResponse wr = (HttpWebResponse)we.Response;
				StringBuilder error = new StringBuilder();
				error.Append(we.Message).Append(" <br/>Reason: ").Append(wr.StatusDescription).Append("<br><br>");

				if (wr.Headers["oauth_signature_base_debug"] != null) {
					error.Append("<br><br>").Append(signatureBase);
					error.Append("<br><br>").Append(wr.Headers["oauth_signature_base_debug"].ToString());
				}

				if (wr.Headers["oauth_signature_debug"] != null) {
					error.Append("<br><br>").Append(sig);
					error.Append("<br><br>").Append(wr.Headers["oauth_signature_debug"].ToString());
				}
				throw new Exception(error.ToString());
			}

			return requestToken;
		}

		/// <summary>
		/// Step #2: Authenticate the request token. This method builds a url to send the user off to, so they can login with their FT login.  After logging in, the FT API
		///  will redirect them to the callbackUrl supplied.  We send the requestToken in the url.  When our callback url is called, it will contain a querystring parm
		///  with the authorized request token (if the user logged in successfully).
		/// </summary>
		/// <param name="token"></param>
		/// <param name="callbackUrl"></param>
		/// <returns></returns>
		public String RequestUserAuth(String token, String callbackUrl) {
			var builder = new UriBuilder(UserAuthorizeUrl); // We've hardcoded to use WebLink login in our url constant
			var collection = new NameValueCollection();
			var queryParameters = new NameValueCollection();

			if (builder.Query != null) {
				collection.Add(System.Web.HttpUtility.ParseQueryString(builder.Query));
			}

			if (queryParameters != null)
				collection.Add(queryParameters);

			collection["oauth_token"] = token;

			if (!String.IsNullOrEmpty(callbackUrl)) {
				collection["oauth_callback"] = callbackUrl;
			}

			builder.Query = "";

			return builder.Uri + "?" + FormatQueryString(collection);

		}

		/// <summary>
		/// Step #3:  Trade the authorized request token for an Access Token
		/// </summary>
		/// <param name="requestToken"></param>
		/// <param name="personUrl"></param>
		/// <returns></returns>
		public Token getAccessToken(Token requestToken, out String personUrl) {
			Token accessToken = null; 
			Uri url = new Uri(AccessUrl);
			String nonce = generateNonce();
			String timestamp = GenerateTimeStamp();
			String normalizedUrl = "";
			String normalizedReqParms = "";
			String signatureBase = "";
			String sig = GenerateSignature(url, ConsumerKey, ConsumerSecret, requestToken.Value, requestToken.Secret, "GET", timestamp, nonce, out normalizedUrl, out normalizedReqParms, out signatureBase);
			personUrl = "";

			HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(url);
			String authHeader = buildOAuthHeader(ConsumerKey, nonce, sig, HMACSHA1SignatureType, timestamp, requestToken.Value);
			request.Headers.Add("Authorization", authHeader);
			request.ContentType = "appliation/xml";
			request.Method = "GET";

            try {
				WebResponse webResponse = request.GetResponse();
				StreamReader sr = new StreamReader(webResponse.GetResponseStream());

				if (webResponse.Headers["Content-Location"] != null) {
				    personUrl = webResponse.Headers["Content-Location"].ToString();
				}

				String results = sr.ReadToEnd().Trim();

				String[] tokeninfo = results.Split('&');
				accessToken = new Token();
				accessToken.Value = tokeninfo[0].Replace("oauth_token=", "");
				accessToken.Secret = tokeninfo[1].Replace("oauth_token_secret=", "");
			}
			catch (WebException we) {
				HttpWebResponse wr = (HttpWebResponse)we.Response;
				StringBuilder error = new StringBuilder();
				error.Append(we.Message).Append(" <br/>Reason: ").Append(wr.StatusDescription).Append("<br><br>");

				if (wr.Headers["oauth_signature_base_debug"] != null) {
					error.Append("<br><br>").Append(signatureBase);
					error.Append("<br><br>").Append(wr.Headers["oauth_signature_base_debug"].ToString());
				}

				if (wr.Headers["oauth_signature_debug"] != null) {
					error.Append("<br><br>").Append(sig);
					error.Append("<br><br>").Append(wr.Headers["oauth_signature_debug"].ToString());
				}
				throw new Exception(error.ToString());
			}
			return accessToken;
		}

		*/

    // Supports 2nd party, placing credentials in body of request

    public AuthenticationToken getAccessToken(String personUrl, byte[] creds) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        logger.info("in getAccessToken.");
        logger.info("personUrl = " + personUrl);
        logger.info("creds = " + creds.toString());

        AuthenticationToken accessToken;
        URL url = new URL(getTrustedUrl());
        String nonce = generateNonce();
        String timestamp = generateTimeStamp();
        String normalizedUrl = "";
        String normalizedReqParms = "";
        String signatureBase = "";
        String sig = generateSignature(url, getConsumerKey(), getConsumerSecret(), null, null, "POST",
                timestamp, nonce, normalizedUrl, normalizedReqParms, signatureBase);

        HttpURLConnection request = (HttpURLConnection) url.openConnection();
        request.setFixedLengthStreamingMode(creds.length);
        request.setRequestMethod("POST");  // changed to POST to support 2nd party
        String authHeader = buildOAuthHeader(getConsumerKey(), nonce, sig, HMACSHA1SignatureType, timestamp, null);
        request.setRequestProperty("Authorization", authHeader);
        request.setRequestProperty("Content-Type", "application/xml");
        request.setDoOutput(true);
        request.setDoInput(true);
        request.setUseCaches(false);
        request.setAllowUserInteraction(false);


        request.setRequestProperty("Content-Length", creds.length + "");
        // Get the request stream.

        // Create the form content
        OutputStream out = request.getOutputStream();
        out.write(creds);
        out.close();

        int code = request.getResponseCode();
        logger.info("responseCode:" + code);

        if (code != 200) {
            logger.debug("code is not 200");

            String message = request.getResponseMessage();
            logger.debug("response message = " + message);

            if (request.getErrorStream() != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(request.getErrorStream()));
                String str;
                StringBuffer sb = new StringBuffer();
                while ((str = br.readLine()) != null) {
                    sb.append(str);
                    sb.append("\n");
                }
                br.close();
                String response = sb.toString();
                logger.error("error response is:" + response);
            }

            return null;

        }

        BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream()));
        String str;
        StringBuffer sb = new StringBuffer();
        while ((str = br.readLine()) != null) {
            sb.append(str);
            sb.append("\n");
        }
        br.close();
        String response = sb.toString();
        logger.info("response is:" + response);


        String[] tokeninfo = response.trim().split("&");
        accessToken = new AuthenticationToken();
        accessToken.setAccessToken(tokeninfo[0].replace("oauth_token=", ""));
        accessToken.setTokenSecret(tokeninfo[1].replace("oauth_token_secret=", ""));

        /*
            //Could add this if needed
            if (webResponse.Headers["Content-Location"] != null)
            {
                personUrl = webResponse.Headers["Content-Location"].ToString();
            }
        */
        return accessToken;
    }

    public HttpURLConnection createWebRequestFromPartialUrl(String partialUrl, AuthenticationToken accessToken,
                                                            String httpRequestMethod, String contentType) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        logger.info("In createWebRequestFromPartialUrl.");
        logger.info("partialUrl=" + partialUrl);
        logger.info("accessToken=" + accessToken);
        logger.info("httpRequestMethod=" + httpRequestMethod);
        logger.info("contentType=" + contentType);

        String fullUrl = createAPIUrl(_churchCode, _baseAPIUrl, _apiVersion, partialUrl);
        logger.debug("Request URL: " + fullUrl);
        return createWebRequest(fullUrl, accessToken, httpRequestMethod, contentType);
    }

    private HttpURLConnection createWebRequest(String fullUrl, AuthenticationToken accessToken, String httpRequestMethod, String contentType) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        logger.info("in createWebRequest");
        HttpURLConnection webRequest;

        URL uri = new URL(fullUrl);

        String nonce = generateNonce();
        String timestamp = generateTimeStamp();
        String normalizedUrl = "";
        String normalizedReqParms = "";
        String signatureBase = "";
        String sig = generateSignature(uri, _consumerKey, _consumerSecret, accessToken.getAccessToken(), accessToken.getTokenSecret(), httpRequestMethod,
                timestamp, nonce, normalizedUrl, normalizedReqParms, signatureBase);

        webRequest = (HttpURLConnection) uri.openConnection();
        String authHeader = buildOAuthHeader(_consumerKey, nonce, sig, HMACSHA1SignatureType, timestamp, accessToken.getAccessToken());
        webRequest.setRequestProperty("Authorization", authHeader);
        webRequest.setRequestProperty("Content-Type", contentType);
        webRequest.setDoOutput(true);
        webRequest.setDoInput(true);
        webRequest.setUseCaches(false);
        webRequest.setAllowUserInteraction(false);
        webRequest.setRequestMethod(httpRequestMethod);

        return webRequest;
    }

    // This is only used for first or second party usage.
    // If using Third party - we have F1 generate the login page and accept the credentials.

    public byte[] buildCredentials(String username, String password) {
        logger.info("In buildCredentials.  username: " + username + " password: " + password);
        byte[] data = (username + " " + password).getBytes();
        byte[] byteEncoded = Base64.encodeBase64(data);
        String encodedDataForBody = byteEncoded.toString();
        logger.info("returning encodedData:" + encodedDataForBody);
        return byteEncoded;
    }


    /// <summary>
    /// Generate the signature base that is used to produce the signature
    /// </summary>
    /// <param name="url">The full url that needs to be signed including its non OAuth url parameters</param>
    /// <param name="consumerKey">The consumer key</param>
    /// <param name="token">The token, if available. If not available pass null or an empty String</param>
    /// <param name="tokenSecret">The token secret, if available. If not available pass null or an empty String</param>
    /// <param name="httpMethod">The http method used. Must be a valid HTTP method verb (POST,GET,PUT, etc)</param>
    /// <param name="signatureType">The signature type. To use the default values use <see cref="OAuthBase.SignatureTypes">OAuthBase.SignatureTypes</see>.</param>
    /// <returns>The signature base</returns>

    public String generateSignatureBase(URL url, String consumerKey, String token, String tokenSecret,
                                        String httpMethod, String timeStamp, String nonce, String signatureType,
                                        String normalizedUrl, String normalizedRequestParameters) throws UnsupportedEncodingException {
        logger.info("in generateSignatureBase.");
        logger.info("url:" + url);
        logger.info("consumerKey:" + consumerKey);
        logger.info("token:" + token);
        logger.info("tokenSecret:" + tokenSecret);
        logger.info("httpMethod:" + httpMethod);
        logger.info("timeStamp:" + timeStamp);
        logger.info("nonce:" + nonce);
        logger.info("signatureType:" + signatureType);
        logger.info("normalizedUrl:" + normalizedUrl);
        logger.info("normalizedRequestParams:" + normalizedRequestParameters);

        if (token == null) {
            token = "";
        }

        if (tokenSecret == null) {
            tokenSecret = "";
        }

        if (consumerKey == null || consumerKey.length() == 0) {
            throw new IllegalArgumentException("consumerKey");
        }

        if (httpMethod == null || httpMethod.length() == 0) {
            throw new IllegalArgumentException("httpMethod");
        }

        if (signatureType == null || signatureType.length() == 0) {
            throw new IllegalArgumentException("signatureType");
        }

        List<QueryParameter> parameters = getQueryParameters(url.getQuery());
        parameters.add(new QueryParameter(OAuthVersionKey, OAuthVersion));
        parameters.add(new QueryParameter(OAuthNonceKey, nonce));
        parameters.add(new QueryParameter(OAuthTimestampKey, timeStamp));
        parameters.add(new QueryParameter(OAuthSignatureMethodKey, signatureType));
        parameters.add(new QueryParameter(OAuthConsumerKeyKey, consumerKey));

        if (token.length() > 0) {
            logger.debug("adding queryParameter oauth token");
            parameters.add(new QueryParameter(OAuthTokenKey, token));
        }

        //They need to be sorted properly
        Collections.sort(parameters, new QueryParameterComparer());

        normalizedUrl = url.getProtocol() + "://" + url.getHost();
        if (url.getPort() != -1) {
            if (!((url.getProtocol().equals("http") && url.getPort() == 80) || (url.getProtocol().equals("https") && url.getPort() == 443))) {
                normalizedUrl += ":" + url.getPort();
            }
        }
        normalizedUrl += url.getPath();
        logger.info("normalizedUrl: " + normalizedUrl);
        normalizedRequestParameters = normalizeRequestParameters(parameters);

        StringBuilder signatureBase = new StringBuilder();
        signatureBase.append(httpMethod.toUpperCase()).append("&");
        signatureBase.append(encode(normalizedUrl)).append("&");
        signatureBase.append(encode(normalizedRequestParameters));

        logger.info("returning signatureBase:" + signatureBase);

        return signatureBase.toString();
    }

    /// <summary>
    /// Generates a signature using the specified signatureType
    /// </summary>
    /// <param name="url">The full url that needs to be signed including its non OAuth url parameters</param>
    /// <param name="consumerKey">The consumer key</param>
    /// <param name="consumerSecret">The consumer secret</param>
    /// <param name="token">The token, if available. If not available pass null or an empty String</param>
    /// <param name="tokenSecret">The token secret, if available. If not available pass null or an empty String</param>
    /// <param name="httpMethod">The http method used. Must be a valid HTTP method verb (POST,GET,PUT, etc)</param>
    /// <param name="signatureType">The type of signature to use</param>
    /// <returns>A base64 String of the hash value</returns>

    public String generateSignature(URL url, String consumerKey, String consumerSecret, String token,
                                    String tokenSecret, String httpMethod, String timeStamp,
                                    String nonce, String normalizedUrl, String normalizedRequestParameters,
                                    String signatureBase) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        logger.info("in generateSignature.");
        logger.info("url:" + url);
        logger.info("consumerKey:" + consumerKey);
        logger.info("consumerSecret:" + consumerSecret);
        logger.info("token:" + token);
        logger.info("tokenSecret:" + tokenSecret);
        logger.info("httpMethod:" + httpMethod);
        logger.info("timeStamp:" + timeStamp);
        logger.info("nonce:" + nonce);
        logger.info("normalizedUrl:" + normalizedUrl);
        logger.info("normalizedRequestParams" + normalizedRequestParameters);
        logger.info("signatureBase:" + signatureBase);

        signatureBase = generateSignatureBase(url, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, HMACSHA1SignatureType, normalizedUrl, normalizedRequestParameters);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        String keyString;
        if (tokenSecret == null || tokenSecret.length() == 0) {
            logger.info("tokenSecret is empty");
            keyString = encode(consumerSecret) + "&";
        }
        else {
            logger.info("tokenSecret is not empty");
            keyString = encode(consumerSecret) + "&" + encode(tokenSecret);
        }

        logger.info("generating secret key spec using keyString:" + keyString);
        SecretKeySpec key = new SecretKeySpec((keyString).getBytes(CHARSET), HMAC_SHA1);
        logger.info("initing mac with key");
        mac.init(key);

        logger.info("calling computeHash");
        return computeHash(mac, signatureBase);

    }

    /// <summary>
    /// Generate the timestamp for the signature
    /// </summary>
    /// <returns></returns>
    public String generateTimeStamp() {
        String retVal = String.valueOf(getTs()); 
        logger.info("in generateTimeStamp. timestamp is:" + retVal);
        return retVal;
    }

    /// <summary>
    /// Generate a nonce
    /// </summary>
    /// <returns></returns>
    public String generateNonce() {
        Long ts = getTs();
        String retVal =  String.valueOf(ts + new Random().nextInt());

        logger.info("in generateNonce.  retVal:" + retVal);
        return retVal;
    }

    private Long getTs() {
        return System.currentTimeMillis() / 1000;
    }

    /// <summary>
    /// Helper function to compute a hash value
    /// </summary>
    /// <param name="hashAlgorithm">The hashing algoirhtm used. If that algorithm needs some initialization, like HMAC and its derivatives, they should be initialized prior to passing it to this function</param>
    /// <param name="data">The data to hash</param>
    /// <returns>a Base64 String of the hash value</returns>

    private String computeHash(Mac hashAlgorithm, String data) throws UnsupportedEncodingException {
        logger.info("in computerHash.  data:" + data);
        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("hashAlgorithm");
        }

        if (data == null || data.length() == 0) {
            throw new IllegalArgumentException("data");
        }

        String EMPTY_STRING = "";
        String CARRIAGE_RETURN = "\r\n";

        byte[] bytes = hashAlgorithm.doFinal(data.getBytes(CHARSET));
        String finalHash = new String(Base64.encodeBase64(bytes)).replace(CARRIAGE_RETURN, EMPTY_STRING);
        logger.info("returning from computeHash:" + finalHash);
        return finalHash;
    }

    /// <summary>
    /// Internal function to cut out all non oauth query String parameters (all parameters not begining with "oauth_")
    /// </summary>
    /// <param name="parameters">The query String part of the Url</param>
    /// <returns>A list of QueryParameter each containing the parameter name and value</returns>

    private List<QueryParameter> getQueryParameters(String parameters) {
        logger.info("in getQueryParameters.  params =" + parameters);

        List<QueryParameter> result = new ArrayList<QueryParameter>();

        if (parameters != null) {
            if (parameters.startsWith("?")) {
                parameters = parameters.substring(1);
            }


            if (parameters != null && parameters.length() > 0) {
                String[] p = parameters.split("&");
                for (String s : p) {
                    logger.debug("param:" + s);
                    if (!(s == null || s.length() == 0) && !s.startsWith(OAuthParameterPrefix)) {
                        if (s.indexOf('=') > -1) {
                            String[] temp = s.split("=");
                            result.add(new QueryParameter(temp[0], temp[1]));
                        }
                        else {
                            result.add(new QueryParameter(s, ""));
                        }
                    }
                }
            }
        }
        logger.debug("result.size=" + result.size());

        return result;
    }

    public static String encode(String plain) throws UnsupportedEncodingException {
        logger.info("in encode.  plain=" + plain);
        Map<String, String> ENCODING_RULES = new HashMap<String, String>();
        ENCODING_RULES.put("*", "%2A");
        ENCODING_RULES.put("+", "%2B"); //Changed from 20 to 2B - I think UrlEncoder is doing this correctly, tho.
        ENCODING_RULES.put("%7E", "~");

        if (plain == null) {
            throw new IllegalArgumentException("Cannot encode null object");
        }
        String encoded = "";
        encoded = URLEncoder.encode(plain, CHARSET);
        logger.info("1st encoding:" + encoded);
        for (Map.Entry<String, String> rule : ENCODING_RULES.entrySet()) {
            encoded = applyRule(encoded, rule.getKey(), rule.getValue());
        }
        logger.info("final encoding:" + encoded);
        return encoded;
    }

    private static String applyRule(String encoded, String toReplace, String replacement) {
        return encoded.replaceAll(Pattern.quote(toReplace), replacement);
    }


    /// <summary>
    /// Normalizes the request parameters according to the spec
    /// </summary>
    /// <param name="parameters">The list of parameters already sorted</param>
    /// <returns>a String representing the normalized parameters</returns>

    private String normalizeRequestParameters(List<QueryParameter> parameters) throws UnsupportedEncodingException {
        logger.info("in normalizeRequestParameters.  params size is:" + parameters.size());
        StringBuilder sb = new StringBuilder();
        QueryParameter p = null;
        for (int i = 0; i < parameters.size(); i++) {
            p = parameters.get(i);
            sb.append(encode(p.getName())).append("=").append(encode(URLDecoder.decode(p.getValue(), CHARSET)));
            if (i < parameters.size() - 1) {
                sb.append("&");
            }
        }

        logger.debug("retval is:" + sb.toString());

        return sb.toString();
    }

    private String buildOAuthHeader(String consumerKey, String nonce, String signature,
                                    String signatureMethod, String timestamp, String token) throws UnsupportedEncodingException {
        logger.info("in buildOAuthHeader");
        logger.info("consumerKey:" + consumerKey);
        logger.info("nonce:" + nonce);
        logger.info("signature:" + signature);
        logger.info("signatureMethod:" + signatureMethod);
        logger.info("timestamp:" + timestamp);
        logger.info("token:" + token);

        StringBuilder sb = new StringBuilder();
        sb.append("OAuth oauth_consumer_key=\"").append(encode(consumerKey)).append("\",");
        sb.append("oauth_nonce=\"").append(encode(nonce)).append("\",");
        sb.append("oauth_signature=\"").append(encode(signature)).append("\",");
        sb.append("oauth_signature_method=\"").append(encode(signatureMethod)).append("\",");
        sb.append("oauth_timestamp=\"").append(encode(timestamp)).append("\",");
        if (token != null) {
            sb.append("oauth_token=\"").append(token).append("\",");
        }
        sb.append("oauth_version=\"").append(encode("1.0")).append("\"");

        logger.info("retval=" + sb.toString());
        return sb.toString();
    }

    public AuthenticationToken getNewAuthenticationToken() {
        return new AuthenticationToken();
    }


    /// <summary>
    /// Formats a set of query parameters, as per query String encoding.
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    /*
		private String FormatQueryString(NameValueCollection parameters) {
			var builder = new StringBuilder();

			if (parameters != null) {
				foreach (String key in parameters.Keys) {
					if (builder.Length > 0) builder.Append("&");
					builder.Append(key).Append("=");
					builder.Append(encode(parameters[key]));
				}
			}

			return builder.ToString();
		}
		*/

    /// <summary>
    /// Provides an internal structure to sort the query parameter
    /// </summary>

    class QueryParameter {
        private String name = null;
        private String value = null;

        public QueryParameter(String name, String value) {
            this.name = name;
            this.value = value;
            logger.info("Creating queryParameter.  name:" + name + " value:" + value);
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }
    }

    /// <summary>
    /// Comparer class used to perform the sorting of the query parameters
    /// </summary>

    class QueryParameterComparer implements Comparator {

        public int compare(Object o, Object o1) {
            QueryParameter x = (QueryParameter) o;
            QueryParameter y = (QueryParameter) o1;
            if (x.getName().equals(y.getName())) {
                return x.getValue().compareTo(y.getValue());
            }
            else {
                return x.getName().compareTo(y.getName());
            }
        }
    }


    public class AuthenticationToken {
        //access token and token secret
        private String accessToken;
        private String tokenSecret;

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getTokenSecret() {
            return tokenSecret;
        }

        public void setTokenSecret(String tokenSecret) {
            this.tokenSecret = tokenSecret;
        }

        public String toString() {
            return "token:" + accessToken + " secret:" + tokenSecret;
        }
    }


}
