package Client;

import java.util.HashSet;
import java.math.*;
import Client.entity.KV;
import util.*;
import java.util.HashSet;
import util.AESUtil;
import util.Hash;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.util.Arrays;
import java.util.Vector;


import static Client.Xor_conjuctionXMM.xor.xor_list;
import static Client.Xor_conjuction.xtagitem.xtagitem_list;
import static util.tool.longToBytes;
import Server.server;
public class Xor_conjuctionXMM {
    private static Random random = new Random();
    public static HashSet<String> uniqueKeys;
    private static int K_e = 012;
    private static long K_d = 123;
    private static int K_p = 678;
    private static int K_m = 345;
    private static int K_i = 234;
    private static int K_z = 456;
    private static int K_w = 797;
    public static int K_f = 567;
    public Pairing pairing = PairingFactory.getPairing("C:\\Users\\周超然\\Desktop\\XorMM-conjunction\\a.properties");
    public Element g = pairing.getG1().newRandomElement().getImmutable();


    private int beta;
    static int Try_Times;
    public static byte[][] enc_list;
    static byte[][] xv;
    static byte[][] z_k;
    static byte[][] e;
    public byte[][] key_1;
    public static Element[] xtoken;
    public byte[][] key_value;
    public byte[][] key_k;
    public byte[][] xv_key1;
    static byte[][] f;
    static byte[][] q;
    public static Element[] y ;
    public static Element[] xtag ;
    public static Element[] key_valueElementx;
    public static Element[] xtoken_key1;
    static byte[][] xitem;
    static byte[][] xitemone;
    static byte[][] EMM;
    public static byte[][] XMM;
    public static String[] search_keys = new String[]{"key_s_91", "key_s_92", "key_s_260", "key_s_311"};
    //static byte[][] YMM;
    static byte[][] VMM;
    private static Map<String,byte[]> k_list = new HashMap<String,byte[]>();
    public static Map<String,Integer> leave_map = new HashMap<String,Integer>();
    private static final double SMALL_CONSTANT = 1e-10;
    public static int maxValueNumber = Integer.MIN_VALUE;
    public static int maxCounter = Integer.MIN_VALUE; // 用于记录最大 counter 值
    public Xor_conjuctionXMM(int new_beta){
        beta = new_beta;
    }

    public static class YMM {
        public String key;
        public int counter;
        public byte[] e;
        public Element y;

        // 构造函数
        public YMM(String key, int counter, byte[] e, Element y) {
            this.key = key;
            this.counter = counter;
            this.e = e;
            this.y = y;
        }
    }

//    // 辅助方法：将 byte[] 切分为子数组
//    public static byte[] sliceArray(byte[] array, int start, int end) {
//        byte[] slice = new byte[end - start];
//        for (int i = 0; i < slice.length; i++) {
//            slice[i] = array[start + i];
//        }
//        return slice;
//    }

    // 将 KChangePair_list 放在外部类中
    public static List<KChangePair> KChangePair_list = new ArrayList<>();
    public static Map<Integer, KChangePair> kToPairMap = new HashMap<>();
    public static class KChangePair {
        public int i;
        public int found;
        public int k;
        public int change;

        public KChangePair(int i, int found, int k, int change) {
            this.i = i;
            this.found = found;
            this.k = k;
            this.change = change;
        }
    }

    public static class xor {

        public static xor[] xor_list;
        public byte[] enc_list;
        public Element y;

        // 构造函数
        public xor( byte[] enc_list, Element y) {

            this.enc_list = enc_list;
            this.y = y;
        }
    }
    public static class xtagitem {

        public static xtagitem[] xtagitem_list;
        public  String xSubstring_1;
        public  int xSubstring_2;

        // 构造函数
        public xtagitem( String xSubstring_1, int xSubstring_2) {

            this.xSubstring_1 = xSubstring_1;
            this.xSubstring_2 = xSubstring_2;
        }
    }

    //the setup algorithm for XorMM scheme
    public void XorXMM_setup(KV[] kv_list, int level) throws Exception {
        int table_size = (int) Math.floor(((kv_list.length * 1.23) + beta) / 3);
//        System.out.println("table_size： " + table_size*3);
        EMM = new byte[table_size * 3][];
        XMM = new byte[table_size * 3][];
        key_valueElementx = new Element[kv_list.length];
        xtoken = new Element[kv_list.length];
        xtoken_key1 = new Element[kv_list.length];
        enc_list = new byte[kv_list.length][];
        e = new byte[kv_list.length][];
        key_value = new byte[kv_list.length][];

        // 初始化 maxValueNumber 为正值，防止负数参与数组创建
        if (maxValueNumber <= 0) {
            maxValueNumber = 1;
        }

        // 使用 HashSet 统计不同 key 的数量
        uniqueKeys = new HashSet<>();
        // 正则表达式，用于从 value 中提取数字
        Pattern pattern = Pattern.compile("\\d+");
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
                    Matcher matcher = pattern.matcher(kv.value);
                    if (matcher.find()) {
                        int valueNumber = Integer.parseInt(matcher.group());
                        if (valueNumber > maxValueNumber) {
                            maxValueNumber = valueNumber;
                        }
                    }
                }
            }
        }
        maxCounter = maxCounter + 1;
//        // 输出统计结果
//        System.out.println("不同的 key 数量: " + uniqueKeys.size());
//        System.out.println("最大 counter 值: " + maxCounter);
//        System.out.println("最大的 value 中的数字部分: " + maxValueNumber);

        xv = new byte[kv_list.length][];
        z_k = new byte[kv_list.length][];
        f = new byte[kv_list.length][];
        key_1 = new byte[maxCounter][];
        key_k = new byte[maxCounter][];
        xv_key1 = new byte[kv_list.length][];
        q = new byte[kv_list.length][];
        // 初始化 xitem 数组的每一行
        xitem = new byte[uniqueKeys.size()][maxValueNumber]; // Ensure 2D array is properly sized


        // 初始化 xitemone 数组
        xitemone = new byte[kv_list.length][];
        for (int i = 0; i < kv_list.length; i++) {
            xitemone[i] = new byte[maxValueNumber];  // 也为每一行分配列空间
        }
//System.out.println("kv_list: "+kv_list);
        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_e+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            enc_list[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//            System.out.println("enc_list: "+Arrays.toString(enc_list[i]));
        }

        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_i+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            xv[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//            System.out.println("xv: " + Arrays.toString(xv[i]));

        }


        // 定义一个索引变量，用于控制 key_1 的位置
        int key1Index = 0;

        for (int i = 0; i < kv_list.length; i++) {
            byte[] K_1;

            // 检查 k_list 中是否已经存在 kv_list[i].key 对应的值
            if (k_list.containsKey(kv_list[i].key)) {
                K_1 = k_list.get(kv_list[i].key);
            }
            else {
                // 计算 K_1 的值并将其放入 k_list 中
                K_1 = Hash.Get_Sha_128((K_z + kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key, K_1);
            }
            // 执行加密操作并将加密结果传递给 z_k[i]
            z_k[i] = AESUtil.encrypt(K_1, (kv_list[i].key + "," + i).getBytes());
//            System.out.println("z_k[" + i + "]: " + Arrays.toString(z_k[i]));
        }



        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_d+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            e[i] = AESUtil.encrypt(K,(kv_list[i].value).getBytes());
//            System.out.println("e" + e[i]);
        }

        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            if(k_list.containsKey(kv_list[i].key))
                K = k_list.get(kv_list[i].key);
            else {
                K = Hash.Get_Sha_128((K_f+kv_list[i].key).getBytes());
                k_list.put(kv_list[i].key,K);
            }
            f[i] = AESUtil.encrypt(K,(kv_list[i].key).getBytes());
//             System.out.println("f: "+Arrays.toString(f[i]));
        }

        for (int i = 0; i < kv_list.length; i++) {
            byte[] K;
            K = Hash.Get_Sha_128((K_f + kv_list[i].key).getBytes());
            key_value[i] = AESUtil.encrypt(K, (kv_list[i].value).getBytes());
            Element key_valueElement = Hash.HashToZr(pairing, key_value[i]);
            key_valueElementx[i] = key_valueElement;
//            System.out.println("key_value " + i + ":" + Arrays.toString(key_value[i]));
//            System.out.println("key_valueElementx " + i + ":" + key_valueElement);
        }

//        // 初始化 m 用于 key_k 的索引
//        // 初始化 m 用于 key_k 的索引，m 从 0 开始
//        int m = 0;
//        for (int i = 1; i < search_keys.length; i++) {
//            byte[] K_2;
//            if(k_list.containsKey(search_keys[i])) {
//                K_2 = k_list.get(search_keys[i]);
//            }
//            else {
//                K_2 = Hash.Get_Sha_128((K_f + search_keys[i]).getBytes());
//                k_list.put(search_keys[i], K_2);
//            }
//            // 如果匹配，将加密结果存储到 key_k[m]，并递增 m
//            key_k[m] = AESUtil.encrypt(K_2, (search_keys[i]).getBytes());
//            m++;
////            System.out.println("key_k: " + Arrays.toString(key_k[m - 1]));
//
//        }
//
//        // 用于标记是否已经找到 search_keys[0] 的第一次匹配
//        boolean foundFirstMatch = false;
//
//        for (int i = 0; i < kv_list.length; i++) {
//            byte[] K_1;
//
//            // 检查 k_list 中是否已经存在 kv_list[i].key 对应的值
//            if (k_list.containsKey(kv_list[i].key)) {
//                K_1 = k_list.get(kv_list[i].key);
//            } else {
//                // 计算 K_1 的值并将其放入 k_list 中
//                K_1 = Hash.Get_Sha_128((K_z + kv_list[i].key).getBytes());
//                k_list.put(kv_list[i].key, K_1);
//            }
//
//            // 判断 search_keys[0] 是否等于 kv_list[i].key，且这是第一次找到匹配
//            if (kv_list[i].key.equals(search_keys[0]) && !foundFirstMatch) {
//                // 标记第一次匹配已经找到
//                foundFirstMatch = true;
//                // 从 i 开始，进行 31 次加密操作
//                for (int j = 0; j < maxCounter; j++) {
//                    // 对应的 key_1 数组从 0 开始，存储加密结果
//                    key_1[j] = AESUtil.encrypt(K_1, (search_keys[0] + "," + (i + j)).getBytes());
//                    // 打印调试信息
////                    System.out.println("key_1[" + j + "]: " + Arrays.toString(key_1[j]));
//                }
//                break;
//            }
//        }
//
//
//        int numberx = 0;
//        Set<String> seenValues = new HashSet<>();
//        boolean truth = true;
//        for (int i = 0; i < kv_list.length; i++) {
//            // Check if search_keys[0] equals kv_list[i].key, and this is the first match
//            if (kv_list[i].key.equals(search_keys[0])) {
//                // Loop through search_keys starting from index 1
//                for (int s = 1; s < search_keys.length; s++) {
//                    byte[] K_2 = Hash.Get_Sha_128((K_e + search_keys[s]).getBytes());
//                    byte[] K_3 = Hash.Get_Sha_128((K_w + search_keys[s]).getBytes());
////                    System.out.println("K_2 " + Arrays.toString(K_2));
//
//                    // Loop through values
//                    for (int j = 0; j < maxCounter; j++) {
//                        if (i + j >= kv_list.length) {
//                            break; // Prevent array index out of bounds
//                        }
//                        String currentValue = kv_list[i + j].value;
//
//                        if (seenValues.contains(currentValue)) {
//                            // If value is a duplicate, encrypt with K_3 and store
//                            byte[] encryptedValue = AESUtil.encrypt(K_3, currentValue.getBytes());
//                            xv_key1[numberx] = encryptedValue;
////                            System.out.println("xv_key1 " + numberx + ":" + Arrays.toString(xv_key1[numberx]));
//                            numberx++;
//                        } else {
//                            byte[] encryptValue = AESUtil.encrypt(K_2, currentValue.getBytes());
//                            xv_key1[numberx] = encryptValue;
//                            // If it's the first occurrence, add to seenValues but do not process
//                            seenValues.add(currentValue);
////                            System.out.println("xv_key1 " + numberx + ":" + Arrays.toString(xv_key1[numberx]));
//                            numberx++;
//                        }
//
//                    }
//                    seenValues.clear();
//                }
//                break; // Exit after processing the first match
//            }
//        }
//
//        int indexxx = 0;
//        int XV_number = 0;
//        for (int q = 0; q < search_keys.length - 1; q++) {
//            for (int u = 0; u < key_1.length; u++) {
//                Element xv_key_1element = Hash.HashToZr(pairing, xv_key1[XV_number]);
//                Element zk_key_kElement = Hash.HashToZr(pairing, key_1[u]);
//                Element xtokenelement = xv_key_1element.div(zk_key_kElement);
//                xtoken_key1[indexxx] = xtokenelement;
////            System.out.println(" xtoken_key1: " + indexxx + ":" + xtoken_key1[indexxx]);
//                indexxx++;  // 每次存入后，索引递增
//                XV_number++;
//            }
//        }
//
//
//
//        int indexx = 0;
//        for (int u = 0; u < search_keys.length - 1; u++) {
//            for (int o = 0; o < maxCounter; o++) {
//                Element key_kElement = Hash.HashToZr(pairing, key_k[u]);
//                Element key_1element = Hash.HashToZr(pairing, key_1[o]);
//                Element xtokenelement = g.powZn(key_1element.mul(key_kElement));
//                xtoken[indexx] = xtokenelement;
////                System.out.println("Generated secure tag: " + indexx + ":" + xtoken[indexx]);
//                indexx++;  // 每次存入后，索引递增
//            }
//        }
//
//
//        for (int i = 0; i < maxValueNumber; i++) {
//            byte[] K_2;
//            K_2 = Hash.Get_Sha_128((K_z + "i").getBytes());
//            q[i] = AESUtil.encrypt(K_2,(kv_list[1].key + "i").getBytes());
//        }
//
//
        Element[] y = new Element[xv.length];
//System.out.println("----------------------------------");
        // 主处理逻辑
        for (int i = 0; i < xv.length; i++) {
            // 将 xv[i] 和 z_k[i] 哈希到 Zr 群中
            Element xvElement = Hash.HashToZr(pairing, xv[i]);
            Element zkElement = Hash.HashToZr(pairing, z_k[i]);

            // 计算 y[i] = xvElement / zkElement
            Element yElement = xvElement.div(zkElement).getImmutable();

            // 将结果存储到 y 数组中
            y[i] = yElement;
        }Xor_conjuctionXMM.y = y;
//
//
////System.out.println("----------------------------------");
//        // 将二维数组 xitem 转换为一维数组 xitemone
//        int totalElements = uniqueKeys.size() * maxValueNumber; // 一维数组的总长度
//        BigDecimal[] xitem = new BigDecimal[totalElements]; // 新的一维数组
//// 用于将二维数组的元素传输到一维数组
//
//        Element[] xtag = new Element[xv.length];
//        for (int j = 0; j < kv_list.length; j++) {
//            // 将 byteArrayToDouble 的结果通过哈希映射到某个安全的数学域
//            Element xv_e = Hash.HashToZr(pairing, xv[j]);
//            Element f_e = Hash.HashToZr(pairing, f[j]);
//            // 可以考虑进一步的数学运算，如加密或者生成标签
//            Element xtagelement = g.powZn(xv_e.mul(f_e));
//            xtag[j] = xtagelement;
//            // 存储或输出加密后的结果
//            System.out.println("Generated secure tag: " + xtag[j]);
//        }Xor_conjuctionXMM.xtag = xtag;
//
//        xtagitem_list = new xtagitem[kv_list.length];
//// 现在可以将 y 数组的 Element 类型结果转换为 String
//
//        for (int i = 0; i < Xor_conjuctionXMM.xtag.length; i++) {
//            String xtagString = Xor_conjuctionXMM.xtag[i].toString();  // 将 Element 转换为 String
//            xtagitem_list[i] = new xtagitem(xtagString.substring(0, Math.min(30, xtagString.length())),Integer.parseInt(xtagString.substring(16, Math.min(20, xtagString.length()))));
//        }
//        for (int i = 0; i < Xor_conjuctionXMM.xtag.length; i++) {
////            System.out.println("xtagitem_1[" + i + "]: " + xtagitem_list[i].xSubstring_1);  // 打印转换后的 String
////            System.out.println("xtagitem_2[" + i + "]: " + xtagitem_list[i].xSubstring_2);  // 打印转换后的 String
//        }

        YMM[] ymm_list = new YMM[kv_list.length];

        for (int i = 0; i < kv_list.length; i++) {
            // 从kv_list中获取key和counter，e[i]和y[i]分别从e和y数组中获取
            ymm_list[i] = new YMM(kv_list[i].key, kv_list[i].counter, enc_list[i], y[i]);
//            System.out.println("YMM: " + ymm_list[i].key + ", " + ymm_list[i].counter + ", " + Arrays.toString(ymm_list[i].e) + ", " + Arrays.toString(ymm_list[i].y));
        }

        xor_list = new xor[kv_list.length]; // 创建 xor 类的数组

        for (int i = 0; i < kv_list.length; i++) {
            // 假设 enc_list[i] 和 y[i] 是两个 byte[] 数组
            xor_list[i] = new xor(enc_list[i], y[i]); // 将 enc_list[i] 和 y[i] 传入 xor 构造函数
//            System.out.println("XOR: enc_list=" + Arrays.toString(xor_list[i].enc_list) + ", y=" + Arrays.toString(xor_list[i].y));
            // 打印调试信息
        }



// Before the main loop, initialize a list to store the pairs

        MappingStep2(ymm_list,table_size,level);
        for(int i=0;i<ymm_list.length;i++){
            if(XMM[i]==null){
                XMM[i] = Hash.Get_Sha_128(longToBytes(random.nextInt(1000)));
            }
        }

    }




    void MappingStep2(YMM[] ymm_list, int table_size, int level) throws UnsupportedEncodingException {
        int arrayLength = table_size * 3;
        int blockLength = table_size;
        long[] reverseOrder = new long[arrayLength];
        byte[] reverseH = new byte[arrayLength];
        int HASHES = 3;
        int reverseOrderPos;



        do {
            reverseOrderPos = 0;
            leave_map.clear();
            GGM.clear();
            K_d = random.nextLong();
            byte[] t2count = new byte[arrayLength];
            long[] t2 = new long[arrayLength];



            for (int i = 0; i < xtagitem_list.length; i++) {
                long k = i;
                for (int hi = 0; hi < HASHES; hi++) {
                    String ys = xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2; // 假设你的字节数组使用 UTF-8 编码
                    String y0 = ys + "," + hi;
                    int Node, current;
                    if (leave_map.containsKey(y0)) {
                        current = leave_map.get(y0);
                    } else {
//                        byte[] xxx = Hash.Get_SHA_256((xtagitem_list[(int)k].xSubstring_1 + K_d).getBytes());
//                        System.out.println("yvxxx: " +xxx);
                        byte[] yv = GGM.Tri_GGM_Path(Hash.Get_SHA_256((xtagitem_list[(int)k].xSubstring_1 + K_d).getBytes()), level, tool.TtS((xtagitem_list[(int)k].xSubstring_2), 3, level));

                        current = GGM.Map2Range(Arrays.copyOfRange(yv, 1, 9), table_size, 0);
                        leave_map.put(y0, current);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 11, 19), table_size, 1);
                        leave_map.put(ys + ",1", Node);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 21, 29), table_size, 2);
                        leave_map.put(ys + ",2", Node);
                    }
                    int h = current;
                    t2[h] ^= k;
                    if (t2count[h] > 120) {
//                        System.out.println("Index i: " + i);
//                        System.out.println("Hash h: " + h);
//                        System.out.println("t2count[h]: " + t2count[h]);
                        throw new IllegalArgumentException();
                    }
                    t2count[h]++;
                }
            }



            int[][] alone = new int[HASHES][blockLength];
            int[] alonePos = new int[HASHES];
            for (int nextAlone = 0; nextAlone < HASHES; nextAlone++) {
                for (int i = 0; i < blockLength; i++) {
                    if (t2count[nextAlone * blockLength + i] == 1) {
                        alone[nextAlone][alonePos[nextAlone]++] = nextAlone * blockLength + i;
                    }
                }
            }
            int found = -1;
            while (true) {
                int i = -1;
                for (int hi = 0; hi < HASHES; hi++) {
                    if (alonePos[hi] > 0) {
                        i = alone[hi][--alonePos[hi]];
                        found = hi;
                        break;
                    }
                }
                if (i == -1) {
                    break;
                }
                if (t2count[i] <= 0) {
                    continue;
                }
                long k = t2[i];
                if (t2count[i] != 1) {
                    throw new AssertionError();
                }
                --t2count[i];
                for (int hi = 0; hi < HASHES; hi++) {
                    if (hi != found) {
//                        String iii = xtagitem_list[(int) k].xSubstring_1 + "," + xtagitem_list[(int) k].xSubstring_2 + hi;
                        int h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);  // 进行字符串拼接后，再从 map 中获取
                        int newCount = --t2count[h];
                        if (newCount == 1) {
                            alone[hi][alonePos[hi]++] = h;
                        }
                        t2[h] ^= k;
                    }
                }
                reverseOrder[reverseOrderPos] = k;
                reverseH[reverseOrderPos] = (byte) found;
                reverseOrderPos++;
            }



            Try_Times++;
        } while (reverseOrderPos != xtagitem_list.length);


        List<KChangePair> pairs = new ArrayList<>();
        for (int i = reverseOrderPos - 1; i >= 0; i--) {
            int k = (int) reverseOrder[i];
//            System.out.println("k: " +k);
            int found = reverseH[i];
//            System.out.println("found:  " +found);
            int change = -1;
            byte[] xor = key_value[k];
            for (int hi = 0; hi < HASHES; hi++) {
//                System.out.println("xtagitem_list[" + k + "].xSubstring_1: " +xtagitem_list[(int)k].xSubstring_1);
//                System.out.println("xtagitem_list[" + k + "].xSubstring_2: " +xtagitem_list[(int)k].xSubstring_2);
                Integer h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);
//                System.out.println("h: " +h);
                if(h == null) {
                    continue;
                }
                if (found == hi) {
                    change = h;
                } else {
                    if (XMM[h] == null) {
                        XMM[h] = Hash.Get_Sha_128(longToBytes(random.nextInt(10000)));
                    }
                    xor = tool.Xor(xor, XMM[h]);
                }
            }
            XMM[change] = xor;
            KChangePair pair = new KChangePair(i, found, k, change);
            KChangePair_list.add(pair);
            kToPairMap.put(k, pair);
        }
        // 假设 EMM 是一个字节数组的数组
        int totalSizeBytes = 0;
        for (byte[] emmEntry : XMM) {
            if (emmEntry != null) {
                totalSizeBytes += emmEntry.length; // 每个非空条目的字节数
            }
        }

// 将字节转换为 MB
        double totalSizeMB = totalSizeBytes / (1024.0 * 1024.0);
        System.out.println("XMM 总存储大小: " + totalSizeMB + " MB");

        // After the loop, sort the pairs based on k in ascending order
        Collections.sort(pairs, new Comparator<KChangePair>() {
            @Override
            public int compare(KChangePair o1, KChangePair o2) {
                return Integer.compare(o1.k, o2.k);
            }
        });
// Output the sorted list
        // 输出操作
//        System.out.println("Sorted k and change values:");
        for (KChangePair pair : pairs) {
//            System.out.println("k: " + pair.k + ", found:" + pair.found  + ", change: " + pair.change);
        }
    }


    public long Get_K_d(){
        return K_d;
    }
    ////
    public int Get_K_e() { return K_e; }

    public int Get_K_p(){ return K_p; }

    public int Get_K_m() { return K_m; }

    public int Get_Try_Times(){ return Try_Times; }

    public byte[][] Get_EMM(){ return EMM;}

    public byte[][] Get_XMM(){ return XMM;}

    public byte[][] Get_VMM(){ return VMM;}

    public void Leave_Map_Clear() { leave_map.clear(); k_list.clear();}




}

