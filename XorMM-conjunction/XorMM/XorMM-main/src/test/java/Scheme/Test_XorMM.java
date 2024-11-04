package Scheme;

import Client.entity.KV;
import java.io.*;
import java.util.HashSet;
import Server.server;
import Client.Result;
import util.AESUtil;
import util.Hash;
import Client.Xor_conjuction;
import Client.Xor_conjuctionXMM;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class Test_XorMM {

    public static KV[] kv_list;
    public static String[] search_keys;
    public static HashSet<String> uniqueKeys;
    public static int maxValueNumber = Integer.MIN_VALUE;
    public static int maxCounter = Integer.MIN_VALUE; // 用于记录最大 counter 值
    public static ArrayList<Integer> matchingIndices = new ArrayList<>(); // 用于存储匹配的 i 值

    public static void main(String[] args) throws Exception {
        long startTime = System.currentTimeMillis(); // 开始时间

        //maximum volume length
        int MAX_VOLUME_LENGTH = 37;
        int XOR_LEVEL = (int) Math.ceil(Math.log(MAX_VOLUME_LENGTH) / Math.log(3.0)); // GGM Tree level for xor hash

        //data size
        int power_size = 10;
        int ELEMENT_SIZE = 8192;

        //storage size
        int beta = 0; // parameter for xor hash
        int STORAGE_XOR = (int) Math.floor(((ELEMENT_SIZE * 1.23) + beta) / 3);

        //Search key
        search_keys = new String[]{"key_s_91", "key_s_92", "key_s_260", "key_s_311"};

        //initialize a database
        try {
            BufferedReader reader = new BufferedReader(new FileReader("C:\\Users\\周超然\\Desktop\\XorMM-conjunction\\XorMM\\XorMM-main\\key_value_pairs-8192.txt")); // 请将此路径替换为您的txt文件路径
            String line;
            ArrayList<KV> kvList = new ArrayList<>();
            int counter = 0; // 初始化 counter
            String prevKey = null; // 用于跟踪上一个 key

            while ((line = reader.readLine()) != null) {
                // 检查行是否为空
                if (line.trim().isEmpty()) {
                    continue;
                }

                // 解析每一行，提取 key 和 values
                // 行的格式为：
                // key:  key_s_x   value:  value_s_y value_s_z ...

                // 使用正则表达式来匹配 key 和 values
                Pattern pattern = Pattern.compile("key:\\s*(\\S+)\\s*value:\\s*(.+)");
                Matcher matcher = pattern.matcher(line);
                if (matcher.matches()) {
                    String key = matcher.group(1).trim();

                    // 如果遇到新的 key，重置 counter
                    if (prevKey == null || !key.equals(prevKey)) {
                        counter = 0;
                        prevKey = key;
                    }

                    String valuesPart = matcher.group(2).trim();
                    String[] values = valuesPart.split("\\s+");

                    for (String value : values) {
                        KV kv = new KV();
                        kv.key = key;
                        kv.value = value;
                        kv.counter = counter++;
                        kvList.add(kv);
                    }
                }
            }
            reader.close();
            // 将 kvList 转换为 kv_list 数组
            kv_list = kvList.toArray(new KV[kvList.size()]);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 检查 kv_list 是否初始化成功
        if (kv_list == null || kv_list.length == 0) {
            System.err.println("Error: kv_list is null or empty. Please check the file or data format.");
            return;  // 直接返回，避免后续空指针错误
        }

        // 使用 HashSet 统计不同 key 的数量
        uniqueKeys = new HashSet<>();

        // 正则表达式，用于从 value 中提取数字
        Pattern valuePattern = Pattern.compile("\\d+");

        // 遍历 kv_list 数组
        for (KV kv : kv_list) {
            if (kv != null) {
                uniqueKeys.add(kv.key); // 将 key 添加到 HashSet 中，确保 key 是唯一的

                // 更新最大 counter 值
                if (kv.counter > maxCounter) {
                    maxCounter = kv.counter;
                }

                // 更新字典序最大的 value 中的数字部分
                if (kv.value != null) {
                    Matcher valueMatcher = valuePattern.matcher(kv.value);
                    if (valueMatcher.find()) {
                        int valueNumber = Integer.parseInt(valueMatcher.group());
                        if (valueNumber > maxValueNumber) {
                            maxValueNumber = valueNumber;
                        }
                    }
                }
            }
        }
        maxCounter = maxCounter + 1;

        // 输出统计结果
        System.out.println("不同的 key 数量: " + uniqueKeys.size());
        System.out.println("最大 counter 值: " + maxCounter);
        System.out.println("最大的 value 中的数字部分: " + maxValueNumber);

        // 输出 kv_list 数组的内容
        System.out.println("-------- kv_list 数组内容 --------");
        for (KV kv : kv_list) {
            if (kv != null) {
//                System.out.println("Key: " + kv.key + ", Value: " + kv.value + ", Counter: " + kv.counter);
            }
        }
        System.out.println("----------------------------------");

        System.out.println("---------------------XorMM scheme(our scheme)---------------------");

        //setup phase
        Xor_conjuction xor = new Xor_conjuction(beta);
        xor.XorMM_setup(kv_list, XOR_LEVEL);

        long K_d = xor.Get_K_d();
        int K_e = xor.Get_K_e();

        byte[][] xor_EMM = xor.Get_EMM();

        //query phase
        server xor_server = new server(xor_EMM, MAX_VOLUME_LENGTH, XOR_LEVEL, STORAGE_XOR); // server receives ciphertext
        Result xor_Result = new Result(xor_EMM, MAX_VOLUME_LENGTH, XOR_LEVEL, STORAGE_XOR);
        System.out.println("\nClient is generating token ... keywords:" + (search_keys[0]));
        byte[] tk_key = Hash.Get_SHA_256((search_keys[0] + K_d).getBytes(StandardCharsets.UTF_8)); // search token

        System.out.println("\nServer is searching and then Client decrypts ... ");
        xor_server.Query_Xor(tk_key); // search
        ArrayList<byte[]> C_key = xor_server.Get_C_key(); // client receives results
        byte[] K = Hash.Get_Sha_128((K_e + search_keys[0]).getBytes(StandardCharsets.UTF_8));

        // 解密并与 enc_list 匹配
        ArrayList<Object> sValues = new ArrayList<>(); // 创建用于存储解密后的 s 的列表
        for (int i = 0; i < C_key.size(); i++) { // decryption
            byte[] str_0 = AESUtil.decrypt(K, C_key.get(i));
            if (str_0 != null) {
                // 遍历 enc_list，寻找匹配的加密值
                for (int j = 0; j < kv_list.length; j++) {
                    if (Arrays.equals(C_key.get(i), Xor_conjuction.enc_list[j])) {
                        // 如果找到了匹配项，保存 i 的值到 matchingIndices
                        matchingIndices.add(j);
                        break; // 找到匹配的值后，不需要继续遍历 enc_list，跳出内层循环
                    }
                }
                String s = new String(str_0);
//                System.out.println("Decrypted result for key: " + s);
                sValues.add(s); // 将解密得到的字符串 s 添加到 sValues 列表中
            }
        }

        for (int index : matchingIndices) {
//            System.out.println("Matching index: " + index);
//            System.out.println("enc_list[" + index + "]: " + Arrays.toString(Xor_conjuction.enc_list[index]));
//            System.out.println("y[" + index + "]: " + Xor_conjuction.y[index]);
        }

        Xor_conjuctionXMM xorXMM = new Xor_conjuctionXMM(beta);
        xorXMM.XorXMM_setup(kv_list, XOR_LEVEL);
        long endTime1 = System.currentTimeMillis(); // 结束时间
        long startTime1 = System.currentTimeMillis(); // 开始时间
        xor_server.xflag(tk_key);
        xor_server.DecryptXMM();
        xor_server.MappingStep3();
        Result.decryptXORF(sValues);
        long endTime = System.currentTimeMillis(); // 结束时间
        long endTime11 = System.currentTimeMillis(); // 结束时间
        long elapsedTime = endTime - startTime; // 计算耗时
        long elapsedTime1 = endTime1 - startTime; // 计算耗时
        long elapsedTime11 = endTime11 - startTime1; // 计算耗时
        System.out.println("连接关键词检索总过程所用时间: " + elapsedTime + "毫秒");
        System.out.println("初始化过程所用时间: " + elapsedTime1 + "毫秒");
        System.out.println("查询过程所用时间: " + elapsedTime11 + "毫秒");
//        xor_server.Store_Server("XorMM");


    }
}
