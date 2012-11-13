package com.northridgerochester;

import org.apache.log4j.*;

import java.io.*;
import java.net.*;

/**
 * Created by IntelliJ IDEA.
 * User: lloydmurray
 * Date: Sep 11, 2012
 * Time: 11:01:06 PM
 */
public class SearchPeopleExample {
    public static Logger logger = Logger.getLogger(SearchPeopleExample.class);

    public static void main(String[] args) {
        SearchPeopleExample search = new SearchPeopleExample();
        search.start();
    }

    private void start() {

        String username = "username"; //Your username to login to F1
        String password = "password"; //Password for F1
        String baseAPIUrl = "staging.fellowshiponeapi.com"; //Set to staging for testing
        String churchCode = "churchcode"; //Your church code
        String apiVersion = "v1";
        String f1LoginMethod = "PortalUser";  //Default to portalUser
        String consumerKey = "123"; //Your consumer key
        String consumerSecret = "11z1z1z1-zz11-111z-1111-1zzz11z111z1"; //Your consumer Secret
        String partialUrl = "People/Search?searchFor=Smith"; //Sample URL to search for Smith

        //Authenticate
        try {
            OAuthUtil myOAuth = new OAuthUtil(baseAPIUrl, churchCode, apiVersion, f1LoginMethod, consumerKey, consumerSecret);
            byte[] creds = myOAuth.buildCredentials(username, password);
            OAuthUtil.AuthenticationToken authToken = myOAuth.getAccessToken(creds);
            logger.info("authToken:" + authToken);
            HttpURLConnection httpConn = myOAuth.createWebRequestFromPartialUrl(partialUrl, authToken, "GET", "application/xml");
            logger.info("Content sent! - checking for response.");
            int responseCode = httpConn.getResponseCode();
            logger.info("Response Code: " + responseCode);

            if (responseCode != 200) {
                logger.info("code is not 200");

                String message = httpConn.getResponseMessage();
                logger.info("response message = " + message);

                if (httpConn.getErrorStream() != null) {
                    BufferedReader br = new BufferedReader(new InputStreamReader(httpConn.getErrorStream()));
                    String str;
                    StringBuffer sb = new StringBuffer();
                    while ((str = br.readLine()) != null) {
                        sb.append(str);
                        sb.append("\n");
                    }
                    br.close();
                    String errorResponse = sb.toString();
                    logger.error("error response is:" + errorResponse);
                }

                return;
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(httpConn.getInputStream()));
            String str;
            StringBuffer sb = new StringBuffer();
            while ((str = br.readLine()) != null) {
                sb.append(str);
                sb.append("\n");
            }
            br.close();
            String response = sb.toString();
            logger.info("response=" + response);

        }
        catch (Exception e) {
            logger.error("authenticate", e);
        }

    }

}
