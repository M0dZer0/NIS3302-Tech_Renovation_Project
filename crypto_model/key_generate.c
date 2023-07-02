#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdlib.h>
struct key
{
  unsigned char *data;
  int length;
};
// 返回一个Key类型的函数2
struct key convert_file(char *filename)
{
  unsigned char c;
  FILE *file;
  int i;
  unsigned char *str = NULL;
  size_t str_size = 0;

  i = 0;
  file = fopen(filename, "rb");
  while (fread(&c, 1, 1, file))
  {
    // 将读到的内容c存到字符串中
    str = realloc(str, (str_size + 1) * sizeof(char));
    str[i] = c;
    i++;
    str_size++;
  }
  str = realloc(str, (str_size + 1) * sizeof(char));
  str[i] = '\0'; // 在字符串末尾添加结束符

  fclose(file);

  struct key result;
  result.data = str;
  result.length = str_size;

  return result;
}
int fp_check(FILE *fp)

{

  if (!fp)

  {

    printf("Failed to run command\n");

    return 0;
  }

  return 1;
}

void setKey()

{

  FILE *fp;

  char path[1035];

  /* 执行openssl命令 */

  fp = popen("openssl genpkey -algorithm RSA -out private_key.der -outform DER -pkeyopt rsa_keygen_bits:1024", "r"); // popen()函数执行shell命令

  if (!fp_check(fp))

  {

    return 0;
  }

  pclose(fp);

  fp = popen("openssl asn1parse -in public_key.der -inform DER", "r");

  if (!fp_check(fp))

  {

    return 0;
  }

  pclose(fp);

  fp = popen("openssl rsa -pubout -in private_key.der -out public_key.der -inform DER -outform DER -RSAPublicKey_out", "r");

  if (!fp_check(fp))

  {

    return 0;
  }

  pclose(fp);

  fp = popen("openssl asn1parse  -in public_key.der -inform DER", "r");

  if (!fp_check(fp))

  {

    return 0;
  }

  pclose(fp);
}
void save_key_to_file(char *filename, struct key key_data)
{
  FILE *file = fopen(filename, "wb");
  if (file == NULL)
  {
    printf("Failed to open file for writing\n");
    return;
  }
  fwrite(key_data.data, 1, key_data.length, file); // 三个参数分别是：要写入的数据的指针，每个数据的大小，数据的个数，文件指针
  fclose(file);
}
int main()

{
  setKey();
  struct key pub_key = convert_file("public_key.der");

  struct key pri_key = convert_file("private_key.der");

  printf("pub_key: %s\n", pub_key.data);
  printf("the length of pub_key: %d\n", pub_key.length);
  printf("pri_key: %s\n", pri_key.data);
  printf("the length of pri_key: %d\n", pri_key.length);

  // 保存key到文件中
  save_key_to_file("pub_key_file", pub_key);
  save_key_to_file("pri_key_file", pri_key);
}