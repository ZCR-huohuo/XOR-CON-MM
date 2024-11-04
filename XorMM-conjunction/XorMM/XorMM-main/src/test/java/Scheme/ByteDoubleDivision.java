package Scheme;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class ByteDoubleDivision {

    public static void main(String[] args) {
        byte[] byteArray1 = {-68, -12, -43, -97, -56, -103, -64, 38, 109, 113, -122, 120, 28, -75, 56, 17};
        byte[] byteArray2 = {-45, -78, -12, 75, -90, -11, 63, -90, 11, 24, -101, 25, -1, 13, 100, -18};

        // 将 16 位 byte[] 转换为 double[]
        double[] doubles1 = byteArrayToDoubleArray(byteArray1);
        double[] doubles2 = byteArrayToDoubleArray(byteArray2);

        // 对应位置相除
        double[] resultDoubles = new double[doubles1.length];
        for (int i = 0; i < doubles1.length; i++) {
            resultDoubles[i] = doubles1[i] / doubles2[i]; // 对应位置相除
        }

        // 将结果 double[] 转换回 16 位 byte[]
        byte[] resultByteArray = doubleArrayToByteArray(resultDoubles);
        System.out.println("Result byte array after division: " + Arrays.toString(resultByteArray));

        // 验算：将除法结果的 double[] 与原除数相乘，看看是否能得到原来的 byteArray1
        double[] verificationDoubles = new double[resultDoubles.length];
        for (int i = 0; i < resultDoubles.length; i++) {
            verificationDoubles[i] = resultDoubles[i] * doubles2[i]; // 对应位置相乘
        }

        // 将验算结果转换回 16 位 byte[]，用于和 byteArray1 进行比较
        byte[] verificationByteArray = doubleArrayToByteArray(verificationDoubles);
        System.out.println("Verification byte array: " + Arrays.toString(verificationByteArray));

        // 检查验算结果是否和原 byteArray1 相同
        boolean isEqual = Arrays.equals(byteArray1, verificationByteArray);
        System.out.println("Verification result: " + (isEqual ? "Success! The byte arrays match." : "Failure! The byte arrays do not match."));
    }

    // 将 16 字节的 byte[] 转换为两个 double
    public static double[] byteArrayToDoubleArray(byte[] bytes) {
        if (bytes.length != 16) {
            throw new IllegalArgumentException("Byte array must be exactly 16 bytes long");
        }

        double[] result = new double[2];

        // 前8字节转换为第一个 double
        result[0] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 0, 8)).getDouble();
        // 后8字节转换为第二个 double
        result[1] = ByteBuffer.wrap(Arrays.copyOfRange(bytes, 8, 16)).getDouble();

        return result;
    }

    // 将两个 double 转换为 16 字节的 byte[]
    public static byte[] doubleArrayToByteArray(double[] doubles) {
        if (doubles.length != 2) {
            throw new IllegalArgumentException("Double array must have exactly 2 elements");
        }

        byte[] byteArray = new byte[16];

        // 将第一个 double 转换为前8字节
        byte[] firstDoubleBytes = ByteBuffer.allocate(8).putDouble(doubles[0]).array();
        // 将第二个 double 转换为后8字节
        byte[] secondDoubleBytes = ByteBuffer.allocate(8).putDouble(doubles[1]).array();

        // 合并到一个 16 字节的 byte[]
        System.arraycopy(firstDoubleBytes, 0, byteArray, 0, 8);
        System.arraycopy(secondDoubleBytes, 0, byteArray, 8, 8);

        return byteArray;
    }
}
