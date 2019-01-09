import burp.FaradayConnector;
import burp.models.exceptions.InvalidCredentialsException;
import burp.models.exceptions.InvalidFaradayException;
import burp.models.exceptions.SecondFactorRequiredException;

import java.io.PrintWriter;

public class ExtensionTest {

    public static void main(String[] args) {

        FaradayConnector connector = new FaradayConnector(new PrintWriter(System.out));

        connector.setBaseUrl("http://localhost:5985");
//
//        if (!connector.validateFaradayURL()) {
//            System.out.println("Invalid base url");
//            return;
////        }
//
//        try {
//            connector.login("asdasd", "asdasd");
//        } catch (InvalidCredentialsException e) {
//            e.printStackTrace();
//        } catch (SecondFactorRequiredException e) {
//            e.printStackTrace();
//        } catch (InvalidFaradayException e) {
//            e.printStackTrace();
//        }

    }
}
