import java.io.IOException;
import java.io.InputStream;

public class Main {
    public static void main(String[] args) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("cd .");
        InputStream inputStream = process.getInputStream();
        while (inputStream.available() > 0) {
            System.out.print((char) inputStream.read());
        }
    }
}
