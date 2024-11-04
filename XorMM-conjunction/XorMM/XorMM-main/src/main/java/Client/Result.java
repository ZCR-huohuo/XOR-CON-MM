package Client;


import util.AESUtil;
import util.Hash;

import java.util.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.util.Arrays;

import static Client.Xor_conjuction.xtagitem.xtagitem_list;

import util.GGM;
import util.tool;

import java.io.*;

import static Client.Xor_conjuctionXMM.*;
import static Server.server.*;

public class Result {
    private static final int HASHES = 3;
    private static byte[][] EMM;
//    private static byte[][] resArray;
//    public static int[] XORF;
    private static long K_d = 123;
    public static Element[] xtagelement;
    private static int MAX_VOLUME_LENGTH;
    private static int server_level;
    private static Random random = new Random();
    public static Element[] xflag;
    static int Try_Times = 0;
    public static Element[] xtag_key1 ;
    private static int server_DEFAULT_INITIAL_CAPACITY;
    private ArrayList<byte[]> C_key = new ArrayList<byte[]>();

    public static Pairing pairing = PairingFactory.getPairing("C:\\Users\\周超然\\Desktop\\XorMM-conjunction\\a.properties");
    public Element g = pairing.getG1().newRandomElement().getImmutable();


    // 定义一个类来存储 k, change, found 的值
//    class KChangeFound {
//        int k;
//        int change;
//        int found;
//
//        public KChangeFound(int k, int change, int found) {
//            this.k = k;
//            this.change = change;
//            this.found = found;
//        }
//    }

    public static class xtagitem_flag {

        public static xtagitem_flag[] xtagitem_flaglist;
        public  String xSubstring_1flag;
        public  int xSubstring_2flag;

        // 构造函数
        public xtagitem_flag( String xSubstring_1flag, int xSubstring_2flag) {

            this.xSubstring_1flag = xSubstring_1flag;
            this.xSubstring_2flag = xSubstring_2flag;
        }
    }

    public Result(byte[][] fp,int volume_length, int level,int DEFAULT_INITIAL_CAPACITY){
        EMM = fp;
        MAX_VOLUME_LENGTH = volume_length;
        server_level = level;
        server_DEFAULT_INITIAL_CAPACITY = DEFAULT_INITIAL_CAPACITY;
    }

    public void  Query_Xor(byte[] hash){
        for (int i = 0;i<MAX_VOLUME_LENGTH;i++ ) {
            byte[] father_Node = GGM.Tri_GGM_Path(hash, server_level, tool.TtS(i, 3, server_level));
            int t0 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 1 , 9),server_DEFAULT_INITIAL_CAPACITY,0);
            int t1 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 11, 19),server_DEFAULT_INITIAL_CAPACITY,1);
            int t2 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 21, 29),server_DEFAULT_INITIAL_CAPACITY,2);
            byte[] res = tool.Xor(tool.Xor(EMM[t0], EMM[t1]), EMM[t2]);
            String re_s = new String(res);
//            System.out.println("res: "+Arrays.toString(res));
            C_key.add(res);
        }
//System.out.println("C_key: " + C_key);

    }



// 现在可以将 y 数组的 Element 类型结果转换为 String



    public static void decryptXORF(ArrayList<Object> sValues) throws Exception {
        // 假设必要的导入和类变量已在其他地方声明
        // 例如：Hash, AESUtil, pairing, tool 等

        // 最外层循环，遍历 sValues 中的每个值
        for (int sIndex = 0; sIndex < sValues.size(); sIndex++) {
            Object sValue = sValues.get(sIndex);
            String s = sValue.toString(); // 将 sValue 转换为字符串
            boolean allResOne = true;
            // 内层循环，遍历每个 search_key
            for (int i = 1; i < search_keys.length; i++) {
                String search_key = search_keys[i];

                // 第一步：计算 K = Hash.Get_Sha_128((K_f + search_key).getBytes())
                byte[] K = Hash.Get_Sha_128((K_f + search_key).getBytes());

                // 第二步：计算 key_value = AESUtil.encrypt(K, (s + "," + search_key).getBytes())
                byte[] key_value = AESUtil.encrypt(K, (s).getBytes());

                // 第三步：计算 key_valueElement = Hash.HashToZr(pairing, key_value)
                Element key_valueElement = Hash.HashToZr(pairing, key_value);

                // 输出调试信息
//                System.out.println("key_valueElement " + i + ": " + key_valueElement);

                // 第四步：转换为字符串并提取子字符串
                String xtagString = key_valueElement.toString();

                // 确保子字符串长度不超过 xtagString 的长度
                String xSubstring_1 = xtagString.substring(0, Math.min(10, xtagString.length()));

                // 检查 xtagString 的长度以防止索引越界
                if (xtagString.length() > 11) {
                    int endIndex = Math.min(20, xtagString.length());
                    String xSubstring_2_str = xtagString.substring(11, endIndex);
                    int xSubstring_2;

                    try {
                        xSubstring_2 = Integer.parseInt(xSubstring_2_str);
                    } catch (NumberFormatException e) {
                        // 如果解析失败，跳过当前 search_key
                        continue;
                    }

                    // 第五步：遍历 xtagitem_list[]，寻找匹配的 xSubstring_1
                    int k = -1;
                    for (int j = 0; j < xtagitem_list.length; j++) {
                        if (xtagitem_list[j].xSubstring_1.equals(xSubstring_1)) {
                            k = j;
                            break;
                        }
                    }

                    if (k == -1) {
                        // 未找到匹配项，退出内层循环，继续下一个 sValue
                        allResOne = false;
                        break;
                    }

                    // 第六步：获取对应的 KChangePair
                    KChangeFound targetFound = kToFoundMap.get(k);
                    if (targetFound == null) {
                        System.out.println("未找到对应的 KChangePair，k: " + k);
                        // 跳过当前 search_key
                        allResOne = true;
                        continue;
                    }

                    int foundx = targetFound.found;
                    int changex = targetFound.change;

                    // 第七步：从 leave_map 中获取 t1 和 t2
                    int t1 = -1, t2 = -1;
                    int tCount = 0;
                    for (int hi = 0; hi < HASHES; hi++) {
                        if (hi == foundx) {
                            continue; // 跳过 hi 等于 foundx 的情况
                        }

                        String key = xSubstring_1 + "," + xSubstring_2 + "," + hi;
                        Integer t = leave_map.get(key);

                        if (t == null) continue;

                        if (tCount == 0) {
                            t1 = t;
                            tCount++;
                        } else if (tCount == 1) {
                            t2 = t;
                            break;
                        }
                    }

                    if (t1 != -1 && t2 != -1) {
                        // 第八步：计算 res = XORF[changex] XOR XORF[t1] XOR XORF[t2]
                        int res = tool.Xorint(tool.Xorint(XORF[changex], XORF[t1]), XORF[t2]);

                        // 如果 res 不等于 1，标记为 false
                        if (res != 1) {
                            allResOne = false;
                            break; // 可以退出内层循环，因为已经不满足条件
                        }
                        // 如果 res == 1，继续内层循环
                    } else {
                        // 未找到 t1 或 t2，标记为 false，退出内层循环
                        allResOne = false;
                        break;
                    }
                } else {
                    // xtagString 长度不足，跳过当前 search_key
                    allResOne = false;
                    continue;
                }
            }

            // 如果内层循环结束后，所有的 res 都等于 1，输出当前 sValue
            if (allResOne) {
                System.out.println("所有 res 都为 1，当前 sValue：" + sValue);
            }
            // 继续外层循环的下一个 sValue
        }
    }



    public void MappingStep3() {
        int table_size = (int) Math.floor(((resArray.length * 1.23) ) / 3);
        XORF = new int[table_size * 3];
        int MAX_VOLUME_LENGTH = (int) Math.pow(2, 5);
        int level = (int) Math.ceil(Math.log(MAX_VOLUME_LENGTH) / Math.log(3.0));//GGM Tree level for xor hash
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



            for (int i = 0; i < resArray.length; i++) {
                long k = i;
                for (int hi = 0; hi < HASHES; hi++) {
                    String ys = xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2;
//                    System.out.println("ys: " +ys);
                    String y0 = ys + "," + hi;
//                    System.out.println("y0: " +y0);
                    int Node, current;
                    if (leave_map.containsKey(y0)) {
                        current = leave_map.get(y0);
                    } else {
//                        byte[] xxx = Hash.Get_SHA_256((ymm_list[(int) k].key + K_d).getBytes());
//                        System.out.println("yv: " +xxx);
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
//                        Integer mapValue = leave_map.get(ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
////                        System.out.println("mapValue: " +mapValue);
//                        if (mapValue == null) {
//                            // 可以选择抛出更明确的异常或进行其他逻辑处理
//                            throw new IllegalStateException("Map does not contain the key: " + ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
//                        }
                        int h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);
//                        System.out.println("h: " +h);
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
        } while (reverseOrderPos != resArray.length);

// 创建一个列表来存储每次循环的记录
        List<KChangeFound> records = new ArrayList<>();
// 初始化数组，将每个元素设置为 -1，表示尚未初始化
        Arrays.fill(XORF, -1);
        for (int i = reverseOrderPos - 1; i >= 0; i--) {
            int k = (int) reverseOrder[i];
//            System.out.println("k: " +k);
            int found = reverseH[i];
            int change = -1;
//            xor.xor_list[k] = enc_list[k];
//            System.out.println("enc: " +Arrays.toString(enc_list[k]));
            int xor_x = 1;
            for (int hi = 0; hi < HASHES; hi++) {
                Integer h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);
//                System.out.println("h: " +h);
                if (h == null) {
                    // 处理null情况，可以打印日志、抛出异常，或者赋予默认值
//                    System.out.println("Key not found: " + e[i] + "," + y[i]);
                    continue; // 或者 break，或者赋予 h 一个默认值
                }
                if (found == hi) {
                    change = h;
                } else {
                    if (XORF[h] == -1) {
                        XORF[h] = random.nextInt(10000); // 生成 0 到 9999 之间的随机整数

                    }
//                    System.out.println("XORF: " +XORF[h]);
//                    System.out.println("h_h:   " + h);
                    xor_x = tool.Xorint(xor_x, XORF[h]);

//                    System.out.println("xor_x: " + Arrays.toString(xor_x));
                }
            }
            XORF[change] = xor_x;
            // 记录 k, change, found 的值
            records.add(new KChangeFound(k, change, found));
        }
        // 在循环完成后，按照 k 从小到大排序
        Collections.sort(records, new Comparator<KChangeFound>() {
            @Override
            public int compare(KChangeFound o1, KChangeFound o2) {
                return Integer.compare(o1.k, o2.k);
            }
        });

// 输出排序后的数组
//        System.out.println("排序后的 k, change, found 值：");
        for (KChangeFound record : records) {
//            System.out.println("k: " + record.k + ", change: " + record.change + ", found: " + record.found);
        }

    }

    public ArrayList<byte[]> Get_C_key(){ return C_key; }
    public void Clear(){ C_key.clear();}

    public static void Store_Server(String text) {
        try {
            FileOutputStream file = new FileOutputStream("Server_"+text+".dat");
            for (int i = 0; i < EMM.length; i++) {
                file.write(EMM[i]);
            }
            file.close();
        } catch (IOException e) {
            System.out.println("Error - " + e.toString());
        }
    }



}
