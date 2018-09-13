#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdarg.h>

/*
* 1. 将filter_input 和 filter_output 设为接口
* 2. 端口复用: 可以规定一个协议, 起到反弹shell代理的作用
* 3. 优化效率
* 4. 当流量中出现可以字符(\x7f)或字符串(flag)的时候在流量中标记出来(插入一个[DANGEROUS]?)
* 5. 处理流量的程序: 同时查看多组流量文件, 识别地址, 高亮.....
*/

//socat tcp-l:9981,fork exec:/pwn/catch

#define USE_FAKE_FLAG = 0
// char *PROGRAM = "/pwn/pwn";
// char *FLAG_PATH = "/flag";
// char *PROGRAM = "./binarys/pwn1";
// char *FLAG_PATH = "./flag.txt";
#define PROGRAM   "/pwn/pwn.bak"
#define FLAG_PATH   "/flag"

// #define DEBUG


#define ATK   "[TRAFFIC][attack]:"
#define DFC   "[TRAFFIC][defence]:"
#define DGR   "[DANGEROUS]"

#define ATK_len   ((int)(sizeof(ATK) - 1))
#define DFC_len   ((int)(sizeof(DFC) - 1))
#define DGR_len   ((int)(sizeof(DGR) - 1))


// todo 实现类似printf的参数效果, 是否可以包装一层printf
void log_debug(const char* msg, ...){
  #ifdef DEBUG
  va_list args;
  va_start(args, msg);
  printf(msg, args);
  va_end(args);
  #endif
}

char *read_flag(){
  FILE *fp = fopen(FLAG_PATH, "r");
  char *flag = (char *)malloc(256);
  memset(flag, 0, 256);
  fread(flag, 1, 256, fp);
  fclose(fp);
  log_debug("[+]flag is : %s\n", flag);
  return flag;
}

void get_kmp_array(char *flag, int *arr, int flag_len){
  arr[0] = 1;
  for(int i=1; i<flag_len; ++i){
    if(flag[i] != flag[0]){
      arr[i] = i+1;
    }else{
      int j=0;
      while(flag[i] == flag[j] && i<flag_len){
        arr[i] = i+1;
        ++i;
        ++j;
      }
      if(i >= flag_len){
        break;
      }
      arr[i] = i-j;
    }
  }
  log_debug("the array is:");
  for(int i=0; i<flag_len; ++i){
    log_debug("[+]%d, ", arr[i] );
  }
}


// reuturn 1 if flag in buf else 0
// use kmp
int contain_flag(char *buf, char *flag){
  int contain = 0;
  int flag_len = strlen(flag);
  int buf_len = strlen(buf);

  int kmp_array[flag_len];
  get_kmp_array(flag, kmp_array, flag_len);

  int j=0;
  for(int i=0; i<buf_len; ++i){
    if(buf[i] != flag[j]){
      j=0;
      continue;
    }else{
      while(buf[i] == flag[j] && i<buf_len && j<flag_len){
        ++i;
        ++j;
      }
      if(j >= flag_len){
        contain = 1;
      }
      if(i >= buf_len){
        break;
      }
      --i;
      j -= flag_len - kmp_array[j];
    }
  }
  log_debug("[+]resutl is %d\n", contain );
  return contain;
}

int a_contain_b(char *a, char *b){
  int a_len = strlen(a);
  int b_len = strlen(b);
  for(int i=0; i<=a_len-b_len; ++i){
    if(a[i] == b[0]){
      int j=0;
      while(j<b_len){
        if(a[i] == b[j]){
          ++i;
          ++j;
        }else{
          break;
        }
      }
      if(j>=b_len){
        return 1;
      }
    }
  }
  return 0;
}


// maybe md5? or just encrypt the real flag?
// 160a089f-e092-499a-b69b-f0e8082451cf
char *fake_flag(int len){
  return "160a089f-e092-499a-b69b-f0e8082451cf";
}

//todo modify depends the real flag format
char *tranform_flag(char *flag){
  return flag;
}

char *get_current_time(){
  char *current_time = malloc(0x80);
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  sprintf(current_time, "%d_%d_%d", tm.tm_hour, tm.tm_min, tm.tm_sec);
  return current_time;
}

int read_with_timeout(int fd, void *buf, size_t count, int microseconds){
  fd_set set;
  struct timeval timeout;
  int rv;

  FD_ZERO(&set);
  FD_SET(fd, &set);

  timeout.tv_sec = 1;
  timeout.tv_usec = microseconds;

  rv = select(fd + 1, &set, NULL, NULL, &timeout);
  if(rv == -1){
    return -1;
  }
  else if(rv == 0){
    log_debug("[+]timeout\n");
    return 0;
  }
  else{
    return read(fd, buf, count);
  }
}

// filter \x7f
int filter_output(char *output, int output_len){
  // int output_len = strlen(output);
  for(int i=0; i<output_len; ++i){
    if(output[i] == '\x7f'){
      output[i-1] += 1;
      output[i-2] -= 3;
      output[i-3] += 5;
      return 1;
    }
  }
  return 0;
}

//filter flag, \x7f, \x00 in input
int filter_input(char *input, int input_len){
  int dangerous=0;
  for(int i=0; i<input_len; ++i){
    if(input[i] == 'f'){
      if(strncmp("flag", input+i, 4) == 0){
        log_debug("former input: %s", input);
        memcpy(input+i, "fake", 4);
        log_debug("after filter:%s", input);
        dangerous |= 1;
      }
    }
    if(input[i] == 'b'){
      if(strncmp("base", input+i, 4) == 0){
        log_debug("former input: %s", input);
        memcpy(input+i, "    ", 4);
        log_debug("after filter:%s", input);
        dangerous |= 1;
      }
    }


    else if(input[i] == '\x7f'){
      dangerous |= 1;
      input[i] = (char)(i+37);
    }
    else if(input[i] == '\x00'){
      dangerous |= 1;
      input[i] = (char)(i+73);
    }
  }
  return dangerous;
}

// parament ret_val is the return value of function filter_input/output
// return 1 if input/output contain dangerous words, else 0
int is_dangerous(int ret_val){
  return ret_val == 1;
}

void generate_traffic_path(char *path){
  memcpy(path, "/tmp/", 5);
  strcat(path, get_current_time());
  strcat(path, ".traffic");
}


void proxy(int inpipefd[2], int outpipefd[2]){
  struct timespec *wait_time = malloc(sizeof(struct timespec));
  wait_time->tv_sec = 0;
  wait_time->tv_nsec = 1000000; //1ms
  // int ATK_len = strlen(ATK);
  // int DFC_len = strlen(DFC);
  // int DGR_len = strlen(DGR);
  char buf[1024];
  memset(buf, 0, 1024);
  // char conversation[10240];   //store the whole conversatoin
  // memset(conversation, 0, 10240);

  int cvs_idx=0;
  char *flag = read_flag();
  int flag_len = strlen(flag);
  int kmp_array[flag_len];
  get_kmp_array(flag, kmp_array, flag_len);
  int contain_danger_input = 0; //input contain words such as cat, flag

  char record_path[32] = "/tmp/";
  // strcat(record_path, get_current_time());
  // strcat(record_path, )
  generate_traffic_path(record_path);
  FILE *record = fopen(record_path, "w");
  while(1){
    nanosleep(wait_time, 0);  //todo 是否课题通过设定适当的等待时间来达到既可以通过checker又可以使exp失效的效果

    // read from program
    // store in buf
    // if flag in buf then puts fake flag and save whole conversation to a file
    // else puts real outputs
    while(1){
      int wait_ms = 100;
      #ifdef DEBUG
      wait_ms = 100000;
      #endif
      int msg_len = read_with_timeout(inpipefd[0], buf, 1023, 100);
      if(msg_len == 0){
        break;
      }
      log_debug("[+]return value:%d\n", msg_len);
      // memcpy(conversation+cvs_idx, DFC, DFC_len);
      // cvs_idx += DFC_len;
      fseek(record, 0, SEEK_END);
      fwrite(DFC, 1, DFC_len, record);

      // memcpy(conversation+cvs_idx, buf, msg_len);
      // cvs_idx += msg_len;
      fseek(record, 0, SEEK_END);
      fwrite(buf, 1, msg_len, record);

      if(filter_output(buf, msg_len)){
        fseek(record, 0, SEEK_END);
        fwrite(DGR, 1, DGR_len, record);
      }
      write(1, buf, msg_len);
      memset(buf, 0, msg_len);
    }
    log_debug("[+]start to read input\n");

    // read from attacker and store in buf
    int msg_len = read(0, buf, 1023);
    if(msg_len == 0){
      log_debug("no input, break\n");
      break;
    }
    cvs_idx += ATK_len;
    fseek(record, 0, SEEK_END);
    fwrite(ATK, 1, ATK_len, record);
    cvs_idx += msg_len;
    fseek(record, 0, SEEK_END);
    fwrite(buf, 1, msg_len, record);
    if(filter_input(buf, msg_len)){
      fseek(record, 0, SEEK_END);
      fwrite(DGR, 1, DGR_len, record);
    }
    write(outpipefd[1], buf, msg_len);
    memset(buf, 0, msg_len);
  }
}



int main(int argc, char** argv){
  // log_debug("this is a debug test %d, %p\n", 123, 0x1234576);
  alarm(60);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  // printf("hello");
  #ifdef DEBUG
  char ch;
  scanf("%c", &ch);
  #endif
  pid_t pid = 0;
  int inpipefd[2];
  int outpipefd[2];
  char buf[256];
  char msg[256];
  int status;

  pipe(inpipefd);
  pipe(outpipefd);
  pid = fork();
  if (pid == 0)
  {
    // Child
    dup2(outpipefd[0], STDIN_FILENO);
    dup2(inpipefd[1], STDOUT_FILENO);
    dup2(inpipefd[1], STDERR_FILENO);

    //ask kernel to deliver SIGTERM in case the parent dies
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    //replace tee with your process
    execl(PROGRAM, "tee", (char*) NULL);
    log_debug("open program error");
    // Nothing below this line should be executed by child process. If so,
    // it means that the execl function wasn't successfull, so lets exit:
    exit(1);
  }
  // The code below will be executed only by parent. You can write and read
  // from the child using pipefd descriptors, and you can send signals to
  // the process using its pid by kill() function. If the child process will
  // exit unexpectedly, the parent process will obtain SIGCHLD signal that
  // can be handled (e.g. you can respawn the child process).

  //close unused pipe ends
  close(outpipefd[0]);
  close(inpipefd[1]);

  // Now, you can write to outpipefd[1] and read from inpipefd[0] :
  // printf("2hello");
  proxy(inpipefd, outpipefd);

  kill(pid, SIGKILL); //send SIGKILL signal to the child process
  waitpid(pid, &status, 0);
}
