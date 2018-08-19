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

// #define DEBUG

// char *PROGRAM = "/usr/bin/tee";
int USE_FAKE_FLAG = 0;
char *PROGRAM = "./test_bins/login";
char *FLAG_PATH = "./flag.txt";
// char *FLAG_PATH = "./test_bins/login";



char *ATK = "[attack]:";
char *DFC = "[defence]:";

char *read_flag(){
  FILE *fp = fopen(FLAG_PATH, "r");
  char *flag = (char *)malloc(256);
  memset(flag, 0, 256);
  fread(flag, 1, 256, fp);
  fclose(fp);
#ifdef DEBUG
  printf("flag is : %s\n", flag);
#endif
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
  #ifdef DEBUG
  puts("the array is:");
  for(int i=0; i<flag_len; ++i){
    printf("%d, ", arr[i] );
  }
  #endif
}


// reuturn 1 if flag in buf else 0
// use kmp
int contain_flag(char *buf, char *flag, int *kmp_array){
  int contain = 0;
  int flag_len = strlen(flag);
  int buf_len = strlen(buf);

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
  // return 0;
  #ifdef DEBUG
  printf("resutl is %d\n", contain );
  #endif
  return contain;

}

// maybe md5? or just encrypt the real flag?
char *fake_flag(int len){
  return 0; //todo
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

  timeout.tv_sec = 0;

#ifdef DEBUG
    timeout.tv_usec = microseconds*10;
#else
    timeout.tv_usec = microseconds;
#endif

  rv = select(fd + 1, &set, NULL, NULL, &timeout);
  if(rv == -1){
    return -1;
  }
  else if(rv == 0){
#ifdef DEBUG
    printf("timeout\n");
#endif
    return 0;
  }
  else{
    return read(fd, buf, count);
  }

}

// program must first print sth, and then read input
void proxy(int inpipefd[2], int outpipefd[2]){
  struct timespec *wait_time = malloc(sizeof(struct timespec));
  wait_time->tv_sec = 0;
  wait_time->tv_nsec = 1000000; //1ms
  int ATK_len = strlen(ATK);
  int DFC_len = strlen(DFC);
  char buf[1024];
  memset(buf, 0, 1024);
  char conversation[10240];   //store the whole conversatoin
  memset(conversation, 0, 10240);
  int cvs_idx=0;
  char *flag = read_flag();
  int flag_len = strlen(flag);
  int kmp_array[flag_len];
  get_kmp_array(flag, kmp_array, flag_len);
  while(1){
    nanosleep(wait_time, 0);

    // read from program
    // store in buf
    // if return flag the puts fake flag and save whole conversation to a file
    // else puts what program puts
    while(1){
      int msg_len = read_with_timeout(inpipefd[0], buf, 1023, 100);
#ifdef DEBUG
      printf("return value:%d\n", msg_len);
#endif
      if(msg_len == 0){
        break;
      }
      memcpy(conversation+cvs_idx, DFC, DFC_len);
      cvs_idx += DFC_len;
      memcpy(conversation+cvs_idx, buf, msg_len);
      cvs_idx += msg_len;

      if(contain_flag(buf, flag, kmp_array)){
        #ifdef DEBUG
        printf("an successful exp detected(size %d): ", cvs_idx);
        puts(conversation);
        #endif
        FILE *cvs_fp = fopen(get_current_time(), "w");
        fwrite(conversation, 1, cvs_idx, cvs_fp);
        fclose(cvs_fp);
        if(USE_FAKE_FLAG){
          puts(fake_flag(32)); //todo repalce the real flag
        }else{
          puts(buf);
        }
      }else{
        // puts(buf);
        write(2, buf, msg_len);
      }
      memset(buf, 0, msg_len);
    }
#ifdef DEBUG
    printf("start to read input\n");
#endif

    // read from attacker and store in buf
    int msg_len = read(0, buf, 1023);
    if(msg_len == 0){
      break;
    }
    memcpy(conversation+cvs_idx, ATK, ATK_len);
    cvs_idx += ATK_len;
    memcpy(conversation+cvs_idx, buf, msg_len);
    cvs_idx += msg_len;
    write(outpipefd[1], buf, msg_len);
    memset(buf, 0, msg_len);
  }
}

int main(int argc, char** argv){
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
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
    puts("open program error");
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
  proxy(inpipefd, outpipefd);

  kill(pid, SIGKILL); //send SIGKILL signal to the child process
  waitpid(pid, &status, 0);
}
