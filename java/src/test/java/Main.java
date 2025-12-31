import org.example.Reqrio;
import org.example.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        Reqrio reqrio = new Reqrio();
        Response response = reqrio.get("https://www.baidu.com");
        IO.println(response.toString());
    }
}