#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ENABLE_DEBUG 0

//#define PTRACE_PEEKTEXT 1
//#define PTRACE_POKETEXT 4
//#define PTRACE_ATTACH	16
//#define PTRACE_CONT 	7
//#define PTRACE_DETACH   17
//#define PTRACE_SYSCALL	24
#define CPSR_T_MASK		( 1u << 5 )

#define  MAX_PATH 0x100

//通过进程名获取pid
int find_pid_of(const char* process_name){
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE* fp;
	char filename[32];
	char cmdline[256];

	struct dirent* entry;

	if(process_name == NULL)
		return -1;

	dir = opendir("/proc");
	if(dir == NULL)
		return -1;

	while((entry = readdir(dir)) != NULL){
		id = atoi(entry->d_name);
		if(id != 0){
			sprintf(filename, "/proc/%d/cmdline", id);
			fp = fopen(filename, "r");
			if(fp){
				fgets(cmdline, sizeof(cmdline), fp);
				fclose(fp);

				if(strcmp(process_name, cmdline) == 0){
					pid = id;
					break;
				}
			}
		}
	}

	closedir(dir);

	return pid;
}

int ptrace_attach(int nPid){
	if(ptrace(PTRACE_ATTACH, nPid, NULL, 0) < 0){
		return -1;
	}else{
		int stat_loc = 0;
		waitpid(nPid, &stat_loc, WUNTRACED);
		return 0;
	}
}

int ptrace_detach(pid_t pid){
	if(ptrace(PTRACE_DETACH, pid, NULL, 0) < 0){
		perror("ptrace_detach error:");
		return -1;
	}else{
		return 0;
	}
}

//int ptrace_getregs(int nPid, void* data){
//	return ptrace(PTRACE_GETREGS, nPid, NULL, data);
//}


//获取指定模块在指定进程中的基址
void* get_module_base(pid_t pid, const char* module_name){
	FILE* fp;
	long addr = 0;
	char* pch;
	char filename[32];
	char line[1024];

	if(pid < 0){
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	}else{
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if(fp != NULL){
		while(fgets(line, sizeof(line), fp)){
			if(strstr(line, module_name)){
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);

				if(addr == 0x8000)
					addr = 0;

				break;
			}
		}
		fclose(fp);
	}

	return (void*)addr;
}


int getRemoteAddr(int nPid, const char* module_name, int* func){
	int* localmod = (int*)get_module_base(-1, module_name);
	int* remoteMod = (int*)get_module_base(nPid, module_name);
	int nRet = (int)remoteMod + (int)func - (int)localmod;
	printf("getRemoteAddr modName:%s \r\n localMod:%X, remoteMod:%X, func:%x, nRet:%x\r\n",
			module_name, localmod, remoteMod, (int)func, nRet);
	return nRet;
}

//获取目标进程寄存器的值
int ptrace_getregs(pid_t pid, struct pt_regs* regs){
	if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0){
		perror("ptrace_getregs:");
		return -1;
	}
	return 0;
}

//设置目标进程的寄存器
int ptrace_setregs(pid_t pid, struct pt_regs* regs){
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0){
		perror("ptrace_setregs:");
		return -1;
	}
	return 0;
}

//把代码写入目标进程
int ptrace_writedata(pid_t pid, unsigned int dest, unsigned char* data, size_t size){
	unsigned char* srcTmp = data;
	unsigned int destTmp = dest;;
	int n = size / 4;
	int remain = size % 4;
	int count  = 0;
	for(count = 0; count < n; count++){
		ptrace(PTRACE_POKEDATA, pid, destTmp, *(unsigned int*)srcTmp);
		destTmp += 4;
		srcTmp += 4;
	}

	if(remain){
		unsigned long n1 = ptrace(PTRACE_PEEKDATA, pid, 0);
		for(int i = 0; i < remain; i++){
			((unsigned char*)&n1)[i] = srcTmp[i];
		}
		ptrace(PTRACE_POKEDATA, pid, destTmp, n1);
	}


//	uint32_t i, j, remain;
//	uint8_t* laddr;
//	union u{
//		long val;
//		char chars[sizeof(long)];
//	}d;
//
//	j = size /4;
//	remain = size % 4;
//
//	laddr = data;
//
//	for(i = 0; i < j; i++){
//		memcpy(d.chars, laddr, 4);
//		ptrace(PTRACE_POKETEXT, pid, dest, (void*)&d.val);
//		dest += 4;
//		laddr += 4;
//	}
//
//	if(remain > 0){
//		d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, (void*)&d.val);
//		for(i = 0; i < remain; i++){
//			d.chars[i] = *laddr++;
//		}
//		ptrace(PTRACE_POKETEXT, pid, dest, (void*)&d.val);
//	}
	return 0;
}

int ptrace_readdata(pid_t pid, unsigned int dest, unsigned char* data, size_t size){
	long v15 = 0;
	unsigned int srcTmp = dest;
	int k = size / 4;
	int remain = size % 4;
	int count  = 0;
	for(count = 0; count < k; count++){
		long n = 0;
		n = ptrace(PTRACE_PEEKDATA, pid, srcTmp, 0);
		*(long*)data = n;
		srcTmp += 4;
		data += 4;
	}

	if(remain){
		long n = 0;
		n = ptrace(PTRACE_PEEKDATA, pid, srcTmp, 0);
		for(int i = 0; i < remain; i++){
			data[i] = ((unsigned char*)n)[i];
		}
	}

	return 0;
}

int ptrace_continue(pid_t pid){
	if(ptrace(PTRACE_CONT, pid, NULL, 0) < 0){
		perror("ptrace_cont");
		return -1;
	}
	return 0;
}

int ptrace_call(pid_t pid, uint32_t addr, long* params, uint32_t num_params, struct pt_regs* regs){
	int nUseCount = 0;
	long* pArg = (long*)regs;
	printf("ptrace_call pid:%d, addr:%x, numParams:%d\r\n", pid, addr, num_params);
	for(int i = 0; i < num_params; i++){
		printf("params[%d] = %d ", i, params[i]);
	}
	printf("\r\n");
	long* pParm = params;
	while(nUseCount <= 3 && nUseCount < num_params){
		*pArg++ = *pParm++;
		nUseCount++;
	}

	printf("nUseCount:%d, numParams:%d\r\n", nUseCount, num_params);
	if(nUseCount < num_params){
		int nSpSize = 4*(num_params - nUseCount);
		regs->ARM_sp -= nSpSize;
		printf("ptrace_call->ptrace_writedata\r\n");
		ptrace_writedata(pid, regs->ARM_sp, (unsigned char*)&params[nUseCount], nSpSize);
	}

	printf("ptrace_call->change ARM_pc\r\n");
	regs->ARM_pc = addr;
	if(regs->ARM_pc & 1){
		regs->ARM_pc = addr & 0xFFFFFFFE;
		regs->ARM_cpsr = regs->ARM_cpsr | 0x20;
	}else{
		regs->ARM_cpsr = regs->ARM_cpsr & 0xFFFFFFDF;
	}

	regs->ARM_lr = 0;

	printf("ptrace_call->ptrace_setregs\r\n");
	if(ptrace_setregs(pid, regs) == -1){
		return -1;
	}

	printf("ptrace_call->ptrace_continue1\r\n");
	if(ptrace_continue(pid) != -1){
		int nstat = 0;
		waitpid(pid, &nstat, 2);
		while(nstat != 0xB7F){
			if(ptrace_continue(pid) == -1){
				return -1;
			}
			waitpid(pid, &nstat, 2);
		}
	}

//	uint32_t i;
//	for(i = 0; i < num_params && i < 4; i++){
//		regs->uregs[i] = params[i];
//	}
//
//	//多于第四个的参数压入栈中
//	if(i < num_params){
//		regs->ARM_sp -= (num_params - i)*sizeof(long);
//		ptrace_writedata(pid, (uint8_t*)regs->ARM_sp, (uint8_t*)&params[i], (num_params - i)*sizeof(long));
//	}
//	regs->ARM_pc = addr;
//
//	if(regs->ARM_pc & 1){
//		/*thumb*/
//		regs->ARM_pc &= (~1u);
//		regs->ARM_cpsr |= CPSR_T_MASK;
//	}else{
//		/* arm */
//		regs->ARM_cpsr & ~CPSR_T_MASK;
//	}
//	//目标进程执行完之后暂停
//	regs->ARM_lr = 0;
//
//	printf("------------call end start----------\r\n");
//		for(int i = 0; i <= 15; i++){
//			printf("r%d:%08X ", i, regs->uregs[i]);
//		}
//		printf("\r\n-----------------------------------\r\n");
//
//	if(ptrace_setregs(pid, regs) == -1){
//		return -1;
//	}
//	if(ptrace_continue(pid) == -1){
//		return -1;
//	}
//
//	//等待目标进程执行完成
//	int stat = 0;
//	printf("waitpid\r\n");
//	waitpid(pid, &stat, WUNTRACED);
//	printf("waitpid:%d\r\n", stat);
//	while(stat != 0xb7f){
//		printf("waitpid:while(stat != 0xb7f)\r\n");
//		if(ptrace_continue(pid) == -1){
//			return -1;
//		}
//		waitpid(pid, &stat, WUNTRACED);
//		printf("waitpid(pid, &stat, WUNTRACED);stat:%d\r\n", stat);
//	}

	return 0;
}

//int ptrace_errno(pid_t pid, struct pt_regs* regs){
//	int errno_addr = getRemoteAddr(pid, "")
//	if(remote_call(pid, "errno", ))
//}

int remote_call(pid_t pid, char* name, uint32_t addr, long* params, uint32_t num_params, struct pt_regs* regs){
	printf("Inject remote call %s, addr:%x\r\n", name, addr);
	printf("args:");
	for(int i = 0; i < num_params; i++){
		printf("arg[%d] = %d ", i, params[i]);
	}
	printf("\r\n");
	if(ptrace_call(pid, addr, params, num_params, regs) < 0){
		return -1;
	}
	printf("remote_call->ptrace_getregs\r\n");
	if(ptrace_getregs(pid, regs) < 0){
		return -1;
	}
	printf("------------call end regs----------\r\n");
	for(int i = 0; i <= 15; i++){
		printf("r%d:%08X ", i, regs->uregs[i]);
	}
	printf("\r\n-----------------------------------\r\n");
	return 0;
}


//将模块注入指定进程
int inject_remote_process(pid_t target_pid, const char* library_path, const char* function_name, void* param, size_t param_size){
	struct pt_regs regs;
	struct pt_regs saveRegs;	//保存的寄存器环境

	printf("start injecting %d\r\n", target_pid);
	if(ptrace_attach(target_pid) < 0){
		perror("attach error:");
		return -1;
	}

	if(ptrace_getregs(target_pid, &regs) < 0){
		perror("getregs error:");
		return -1;
	}

	memcpy(&saveRegs, &regs, sizeof(pt_regs));

	unsigned int raddr = getRemoteAddr(target_pid, "/system/lib/libc.so", (int*)mmap);
	printf("target mmap addrss:%x\r\n", raddr);

	//test
	int n = (int)mmap(0, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	printf("local mmap ret:%x\r\n", n);

	long nArg[10] = {0};
	nArg[0] = 0;
	nArg[1] = 1024;
	nArg[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
	nArg[3] = MAP_ANONYMOUS | MAP_PRIVATE;
	nArg[4] = 0;
	nArg[5] = 0;
	if(remote_call(target_pid, (char*)"mmap", raddr, nArg, 6, &regs) < 0){
		perror("call target mmap error:");
		printf("remote_call error!\r\n");
		return -1;
	}

	int uResult = (int)regs.ARM_r0;
	printf("target mmap base:%x\r\n", uResult);
	unsigned int remote_dlopen = getRemoteAddr(target_pid, "/system/bin/linker", (int*)&dlopen);
	printf("target dlopen address:%x\r\n", remote_dlopen);
	int nPathLen = strlen((const char*)library_path);
	ptrace_writedata(target_pid, uResult, (unsigned char*)library_path, nPathLen + 1);
	nArg[0] = uResult;
	nArg[1] = 0;
	if(remote_call(target_pid, "dlopen", remote_dlopen, nArg, 2, &regs) < 0){
		perror("target dlopen error:");
		return -1;
	}

	//read test
	char szBuffer[0x256] = {0};
	ptrace_readdata(target_pid, uResult, (unsigned char*)szBuffer, 0x50);
	for(int i = 0; i < 0x50; i++){
		printf("%02X", szBuffer[i]);
	}
	printf("\r\n");
	printf("szBuffer = %s\r\n", szBuffer);

	int nSolib = (int)regs.ARM_r0;
	printf("dlopen result:%x\r\n", nSolib);

	//show test
	printf("remote dl base:%x <<<<<<<<<<\r\n", (int)get_module_base(target_pid, "/data/local/tmp/libso.so"));

	unsigned int fdlsym = getRemoteAddr(target_pid, "/system/bin/linker", (int*)&dlsym);
	printf("target dlsym address:%x\r\n", nSolib);
	int nfunNameLen = strlen((char*)function_name);
	ptrace_writedata(target_pid,uResult + MAX_PATH, (unsigned char*)function_name, nfunNameLen + 1);

	nArg[0] = nSolib;
	nArg[1] = uResult + MAX_PATH;
	if(remote_call(target_pid, "dlsym", fdlsym, nArg, 2, &regs) < 0){
		perror("call target dlsym error:");
		return -1;
	}
	int Hookfunc = (int)regs.ARM_r0;
	printf("target %s address:%x\r\n", library_path, nSolib);

	int nLen = strlen((const char*)function_name);
	unsigned int pargs = uResult + MAX_PATH*2;
	ptrace_writedata(target_pid, pargs, (unsigned char*)function_name, nLen + 1);
	if(remote_call(target_pid, (char*)function_name, (uint32_t)Hookfunc, (long int*)pargs, 0, &regs) < 0){
		printf("call target %s error.", function_name);
		return -1;
	}

	ptrace_setregs(target_pid, &saveRegs);
	ptrace_detach(target_pid);


	return 0;
}

int main(int argc, char* argv[]){
//	if(argc < 2){
//		printf("arg too less.");
//		return 0;
//	}
	printf("++++++++++++++++++++++++ inject run ++++++++++++++++++++\r\n");
	char *pn = "com.k.hookjava";/*argv[1];*/
	char *is = "/data/local/tmp/libso.so";
//	printf("%s\n", pn);
//	printf("%s\n", is);
//
//	printf("%s %s\r\n", argv[1], argv[2]);

	pid_t target_pid;
	target_pid = find_pid_of(pn);
	printf("pid: %d\n", target_pid);

	__android_log_print(ANDROID_LOG_DEBUG, "hook", "hook pid:%d\n", target_pid);

//	//往指定进程中注入so
//	int ret = inject_remote_process(target_pid, is,
//			argv[3], (void*) "I'm parameter!",
//			strlen("I'm parameter!"));
	int ret = inject_remote_process(target_pid, is, "_Z4Hookv", (void*)"parame", strlen("parame"));

	printf("inject remote process ret = %d\n", ret);


	return 0;
}
