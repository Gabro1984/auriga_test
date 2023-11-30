#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DATA_SIZE 252
#define ALIGN_BYTES   4
#define CRC_INIT      0xFFFFFFFF
#define CRC_POLYNOM   0xEDB88320 // reverse 0x04C11DB7

FILE* in_file;
FILE* out_file;

#define LOG(fmt, ...)                                                \
    do                                                               \
    {                                                                \
        FILE* f = fopen("data_out.txt", "ea");                       \
        if (!f)                                                      \
            break;                                                   \
        fprintf(f, fmt " %s %d\n", __VA_ARGS__, __FILE__, __LINE__); \
        fclose(f);                                                   \
    } while (0)

typedef struct Message
{
    uint8_t  type;
    uint8_t  data_len;
    uint8_t  data[MAX_DATA_SIZE];
    uint32_t crc32;
    uint32_t mask;
} Message;

static int parse_line(const char* input, Message* msg)
{
    char* pos = strstr(input, "mess=");

    if (!pos)
    {
        LOG("Error: \"%s\" couldn't be found \n", "mess=");
        return EXIT_FAILURE;
    }
    pos += strlen("mess=");
    msg->type     = *pos++;
    msg->data_len = *pos++;
    strncpy(msg->data, pos, msg->data_len);
    pos += msg->data_len;
    msg->crc32 = *((uint32_t*)pos);
    pos += sizeof(uint32_t);

    pos = strstr(pos, "mask=");

    if (!pos)
    {
        LOG("Error: \"%s\" couldn't be found. \n", "mask=");
        return EXIT_FAILURE;
    }
    pos += strlen("mask=");
    msg->mask = *((uint32_t*)pos);

    return EXIT_SUCCESS;
}

static uint32_t crc32b_calc(const uint8_t* buf, uint32_t len)
{
    int          i, j;
    unsigned int byte, crc, mask;
    i   = 0;
    crc = CRC_INIT;

    while (i < len)
    {
        byte = buf[i];
        crc  = crc ^ byte;
        for (j = 7; j >= 0; j--)
        {
            mask = -(crc & 1);
            crc  = (crc >> 1) ^ (CRC_POLYNOM & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

static uint32_t out_data_len(const uint32_t in_data_len)
{
    uint8_t remainder = in_data_len % ALIGN_BYTES;
    return in_data_len + (ALIGN_BYTES - remainder);
}

static void mask_data(unsigned char* out_data, const Message* in_msg)
{
    uint8_t  byte_num, shift;
    uint16_t i = 0;

    while (i < in_msg->data_len)
    {
        if (i % 2 == 0) // even
        {
            shift       = (i % 4) * 8;
            out_data[i] = in_msg->data[i] & (uint8_t)(in_msg->mask >> shift);
        }
        else
        {
            out_data[i] = in_msg->data[i];
        }
        ++i;
    }
}

static void write_out(const Message* msg)
{
    uint16_t out_data_size = out_data_len(msg->data_len);
    uint8_t  out_data[out_data_size];
    uint32_t out_len = sizeof(msg->type) + 2 * sizeof(msg->data_len) + 2 * sizeof(msg->crc32)
                       + msg->data_len + out_data_size;
    uint8_t* buf = malloc(out_len);
    uint8_t* pos = buf;

    *pos++ = msg->type;
    *pos++ = msg->data_len;
    strncpy(pos, msg->data, msg->data_len);
    pos += msg->data_len;
    strncpy(pos, (uint8_t*)(&msg->crc32), sizeof(msg->crc32));
    pos += sizeof(msg->crc32);
    *pos++ = out_data_size;
    memset(pos, 0, out_data_size);
    mask_data(pos, msg);
    uint32_t crc32 = crc32b_calc(pos, out_data_size);
    pos += out_data_size;
    *(uint32_t*)pos = crc32;

    fwrite(buf, out_len, 1, out_file);
    free(buf);
}

int main(void)
{
    char*   line = NULL;
    size_t  len  = 0;
    Message msg;

    out_file = fopen("data_out.txt", "we");
    if (out_file == NULL)
    {
        exit(EXIT_FAILURE);
    }

    in_file = fopen("data_in.txt", "re");
    if (in_file == NULL)
    {
        LOG("%s", "Error: can't open input file");
        exit(EXIT_FAILURE);
    }

    while (getline(&line, &len, in_file) != -1)
    {
        parse_line(line, &msg);

        if (crc32b_calc(msg.data, msg.data_len) != msg.crc32)
        {
            LOG("Error: wrong crc32 0x%x != 0x%x  \n",
                msg.crc32,
                crc32b_calc(msg.data, msg.data_len));
        }

        write_out(&msg);
    }

    fclose(in_file);
    fclose(out_file);
    if (line)
    {
        free(line);
    }
    exit(EXIT_SUCCESS);
}
