import burp.faraday.FaradayConnector;
import burp.faraday.Workspace;
import burp.faraday.exceptions.BaseFaradayException;
import burp.faraday.exceptions.InvalidCredentialsException;
import burp.faraday.exceptions.InvalidFaradayException;
import burp.faraday.exceptions.SecondFactorRequiredException;

import java.io.PrintWriter;
import java.util.List;

public class ExtensionTest {

    public static void main(String[] args) {

        FaradayConnector connector = new FaradayConnector(new PrintWriter(System.out));

        connector.setBaseUrl("http://localhost:5985");

        try {
            connector.validateFaradayURL();
        } catch (InvalidFaradayException e) {
            e.printStackTrace();
        }

        try {
            connector.login("faraday", "123456");
        } catch (InvalidCredentialsException e) {
            e.printStackTrace();
        } catch (SecondFactorRequiredException e) {
            e.printStackTrace();
        } catch (InvalidFaradayException e) {
            e.printStackTrace();
        } catch (BaseFaradayException e) {
            e.printStackTrace();
        }

        List<Workspace> workspaceList = null;
        try {
            workspaceList = connector.getWorkspaces();
        } catch (BaseFaradayException e) {
            e.printStackTrace();
        }

        System.out.println("workspaceList = " + workspaceList);

    }
}
