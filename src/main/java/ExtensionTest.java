/*
 * Faraday Penetration Test IDE Extension for Burp
 * Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
 * See the file 'LICENSE' for the license information
 */

import burp.faraday.FaradayConnector;
import burp.faraday.exceptions.InvalidCredentialsException;
import burp.faraday.exceptions.InvalidFaradayServerException;
import burp.faraday.exceptions.SecondFactorRequiredException;
import burp.faraday.exceptions.ServerTooOldException;

import java.io.PrintWriter;

public class ExtensionTest {

    public static void main(String[] args) {

        final FaradayConnector faradayConnector = new FaradayConnector(new PrintWriter(System.out));

        faradayConnector.setBaseUrl("http://127.0.0.1:5985/");

        try {
            faradayConnector.validateFaradayURL();
        } catch (InvalidFaradayServerException e) {
            e.printStackTrace();
        } catch (ServerTooOldException e) {
            e.printStackTrace();
        }

        try {
            faradayConnector.login("faraday", "123456");
        } catch (InvalidFaradayServerException e) {
            e.printStackTrace();
        } catch (InvalidCredentialsException e) {
            e.printStackTrace();
        } catch (SecondFactorRequiredException e) {
            e.printStackTrace();
        }

    }
}