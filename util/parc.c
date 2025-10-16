char *Use="Programmed ARChiver; Like cpio -oHbin, but works on odd /proc files."
"\nUsage:\n\n"
"  d=DIR(/proc) j=JOBS(-1) parc GLOBALS -- PROGRAM [-- ROOTS]\n\n"
"where DIR is the directory to run out of (must be cd-able), JOBS is parallelism\n"
"(>0-absolute, <=0-relative to nproc), GLOBALS are $d-relative paths to archive,\n"
"PROGRAM is a series of archival steps to make against ROOTS.  If ROOTS are\n"
"omitted, every top-level direntry of $d matching [1-9]* is used.  Program\n"
"steps are LETTER/entry where LETTER codes are s:stat r:read R:ReadLink and\n"
"these actions are run with each ROOT as a prefix to \"/entry\".  E.g.:\n\n"
"  parc sys/kernel/pid_max uptime meminfo -- s/ r/stat r/io R/exe \\\n"
"       r/cmdline r/schedstat r/smaps_rollup >/dev/shm/$LOGNAME-pfs.cpio\n"
"\nsnapshots what `procs display` needs for most formats/sorts/merges.\n\n`PFA=Y"
" pd -sX; cpio -tv<Y|less` shows needs for your specific case of style X,\n"
"but NOTE parc drops unreadable entries (eg. kthread /exe, otherUser /io) from\n"
"written cpio archives, which are then treated as empty files by `pd`. IF YOU\n"
"HATE cpios, just `| bsdtar --format=X -cf /tmp/new @-` to get tarballs/etc.";
#include <string.h>   // strlen memcpy memset strerror strdup
#include <stdlib.h>   // malloc realloc atoi exit getenv
#include <stdio.h>    // stdout stderr fprintf fwrite
#include <dirent.h>   // opendir readdir closedir DT_DIR
#include <assert.h>   // assert Debugging
#include <errno.h>    // errno EAGAIN EINTR
#include <sys/stat.h> // fstat stat struct stat
#include <unistd.h>   // pipe fork dup2 chdir getuid usleep read close readlink
#include <fcntl.h>    // open O_RDONLY
#include <sys/wait.h> // waitpid
#include <poll.h>     // struct pollfd POLLIN POLLHUP

#define E(fmt, ...) (fprintf(stderr, "parc: " fmt, ##__VA_ARGS__))
void quit(int code, char const *message) {
  if (*message) E("%s\n", message);
  exit(code); }
#define Q(code, fmt, ...) (E(fmt, ##__VA_ARGS__), quit(code, ""))

typedef struct {char *p; int n,a;} Buf; //p)ointer, n Used-NOT-incl-NUL, a)lloc
void BufSize(Buf *b, int a) {           //size a buffer (only growing)
  b->p = realloc(b->p, a);
  b->a = a;
  if (a < b->n) b->n = a; }
void BufSetLen(Buf *b, int n) {         //set len, resizing only if too small
  if (n > b->a) BufSize(b, n);
  b->n = n; }
void BufAddC(Buf *b, char *c, int nC) { //nC + 1: include NUL-term in Buf
  if (b->n + nC + 1 > b->a) BufSize(b, b->n + nC + 1);
  memcpy(&b->p[b->n], c, nC + 1);
  b->n += nC; }
void BufGrow(Buf *b) { BufSize(b, b->a*2); }

//Buf Helpers: Read whole file of unknown, fstat-non-informative size (non-0
//`st` => fill via `fstat` & trust st_size>0); Any size, 0-term readlink(2).
int BufReadFile(Buf *b, char *path, struct stat *st, int nByte) {
  int fd = open(path, O_RDONLY), off = 0, r = -1;
  if (fd == -1) return r;               //Likely vanished between getdents&open
  b->n = 0;
  if (st) {
    if (fstat(fd, st) == -1) goto x;    //Early return virtually impossible
    if (st->st_size > 0) {              //Trust st_size *IF* > 0; May miss..
      BufSetLen(b, st->st_size);        //..actively added; Racy anyway.
      ssize_t nR = read(fd, &b->p[0], st->st_size);
      if (nR == st->st_size) goto x;    //Read everything -> done
      if (nR != -1) off = nR; } }       //Fall to loop on a short|failed read
  while (1) {
    BufSetLen(b, off + nByte);          //Ensure room for read()
    ssize_t nR = read(fd, &b->p[off], nByte);
    if (nR == -1) {
      if (errno == EAGAIN || errno == EINTR) continue;
      b->n = off; goto x;               //Unwind `b` grow on rare failed read
    } else if (nR < nByte) {            //Consider under-count => EOF; AFAIK..
      b->n = off + nR;                  //..this only fails on net FSes.
      break; }
    off += nR; }
  close(fd); return 0;
x:close(fd); return r; }

int BufReadLink(Buf *b, char *path) {   //Reliable POSIX readlink.  Start Buf..
  if (b->a < 128) BufSize(b, 128);      //..small;Loop if answer is maybe trunc.
  int n = b->a;
  while (n == b->a) {
    n = readlink(path, &b->p[0], b->a - 1); // -1 is Room For '\0' WE add
    if (n == b->a) BufGrow(b); }
  if (n <= 0) return -1;
  b->p[n] = '\0';                       //readlink(2) DOES NOT NUL-term
  return 0; }

int ac; char **av;                      // // // GLOBALS & MAIN LOGIC // // //

typedef unsigned short u2_t;            // The 8-bit byte won in early 1970s
typedef struct Rec {    // Saved Data Header;magic=070707 cpio -oHbin compatible
  u2_t magic, dev, ino, mode, uid, gid, nlink, rdev, mtime[2], nmLen, datLen[2];
} __attribute__((__packed__)) Rec;  // 26B Hdr; Support: readFile stat readlink

struct stat st;                         //Reused stat(2) buffer GLOBAL
Buf buf;                                //Reused IO buffer GLOBAL
Rec rec = {.magic= 070707};             //Reused CPIO record header GLOBAL
char Pad0 = '\0', *pad0 = &Pad0;        //Just a 1 byte pad buffer of only \0
#define wD(p, n) (fwrite((p),1,(n),stdout)) //w)rite D)ata to stdout
int jobs=1, soProg=1, eoProg, i;        //GLOBALS for parallel work;Only i moves
uid_t thisUid;

void wH(char *path, int datLen) {       //Write Header to stdout
  int pLen = strlen(path);              assert(pLen > 0);
  rec.nmLen     = (u2_t)(pLen + 1);     //Include NUL terminator
  rec.datLen[0] = (u2_t)((unsigned)datLen >> 16);
  rec.datLen[1] = (u2_t)((unsigned)datLen & 0xFFFF);
  wD(&rec, sizeof rec);                 //Write header, then maybe-padded path
  wD(path, pLen + 1);
  if (pLen%2 == 0) wD(pad0, 1); }

void fromStat(struct stat *st) {        //At least for a single FS like /proc,..
  rec.dev      = (u2_t)(st->st_dev);    //`dev` should never change nor matter..
  rec.ino      = (u2_t)(st->st_ino);    //..so COULD fold in for a 4B inode.
  rec.mode     = (u2_t)(st->st_mode);
  rec.uid      = (u2_t)(st->st_uid);
  rec.gid      = (u2_t)(st->st_gid);
  rec.nlink    = (u2_t)(st->st_nlink);
  rec.rdev     = (u2_t)(st->st_rdev);   //Dev Specials are also very rare
  rec.mtime[0] = (u2_t)((unsigned long)st->st_mtime >> 16);
  rec.mtime[1] = (u2_t)((unsigned long)st->st_mtime & 0xFFFF); }

// 3 A)rchiving calls implement our pico-virtual machine; All end w/fflush to
// ensure parent read() starts w/26B Rec struct to say how much more to read.
void Astat(char *path, struct stat*st){ //Starts archive program for PIDsubDir
  if (stat(path, st) == 0) {        //No clear: fromStat sets EVERY field anyway
    fromStat(st); wH(path, 0); fflush(stdout); } }  //Header ONLY record

void Aread(char *path, struct stat *st) {
  BufReadFile(&buf, path, st, 4096);    //Does fstat ONLY IF `st` not Nil making
  if (buf.n) {                          //..rec.clear either unneeded|unwanted.
    if (st) fromStat(st);               //Global fstat field propagation
    else { rec.mode = 0100444; rec.nlink = 1; } //Regular file r--r--r--
    wH(path, buf.n);                    //Inherit rest from needed last stat
    wD(buf.p, buf.n);                   //Write header & maybe-padded data
    if (buf.n%2 == 1) wD(pad0, 1);
    fflush(stdout); } }

void AReadLink(char *path) {            //Must follow `s` "command"
  if (BufReadLink(&buf, path)==0) {     //rec.clear either unneeded|unwanted
    rec.mode = 0120777; rec.nlink = 1;  //Mark as SymLn;MUST BE KNOWN to be SLn
    wH(path, buf.n + 1);                //Inherit rest from needed last stat
    wD(buf.p, buf.n + 1);               //Write header & maybe-padded data
    if (buf.n%2 == 0) wD(pad0, 1);
    fflush(stdout); } }

void runProgram(int remainder) {        //Main Program Interpreter
  Buf path = {0}; int nPath;            //Starts w/PID-like; Gets /foo added
  int nEntPath[eoProg - soProg];        //Length of /entry
  for (int j=soProg; j < eoProg; j++) nEntPath[j-soProg] = strlen(av[j]);
  for (/**/; i < ac; i++) {             //addDirents/main put all work in av[ac]
    if (i%jobs != remainder) continue;  //For jobs>1, skip not-ours
    BufSetLen(&path, 0);                //Form "ROOT/entry" in `path`
    BufAddC(&path, av[i], nPath = strlen(av[i]));
    for (int j = soProg; j < eoProg; j ++) {
      int nE = nEntPath[j - soProg];    //Below +- 1 skips the [srR]
      BufSetLen(&path, nPath); BufAddC(&path, av[j] + 1, nE - 1);
      if      (av[j][0] == 's') Astat(path.p, &st);  // Act
      else if (av[j][0] == 'r') {       //read; Skip odd perms pass open, not rd
        if (nE == 14 && memcmp(av[j], "r/smaps_rollup", 14) == 0) {
          if (thisUid == 0 || thisUid == st.st_uid) Aread(path.p, NULL); }
        else Aread(path.p, NULL);       //read, ordinary, then readlink
      } else if (av[j][0]=='R') AReadLink(path.p);}}/*if(path.p)free(path.p);*/}

void driveKids() {              //Parallel Kid Launcher-Driver
  int           quiet = !!getenv("q"), j, bytes, dLen,nR,x; // Flag, loop, temps
  int           pipes[jobs][2], kids[jobs];memset(pipes,0,jobs*sizeof pipes[0]);
  struct pollfd fds[jobs];                 memset(fds  ,0,jobs*sizeof fds[0]);
  for (j = 0; j < jobs; j++) {  //Re-try rather than exit on failures since..
    while (pipe(pipes[j])<0) {  //..often one queries /proc DUE TO overloads.
      if (!quiet) E("pipe(): %s (%d)\n", strerror(errno), errno);
      usleep(10000); }          //Microsec; So, 10 ms|100/sec
    pid_t kid;                  //Launch a kid
    while ((kid = fork()) == -1) {
      if (!quiet) E("fork(): %s (%d)\n", strerror(errno), errno);
      usleep(10000); }          //Microsec; So, 10 ms|100/sec
    if (kid == 0) {             //fork: In Kid
      close(pipes[j][0]);       //parent will read from this side of pipe
      if (dup2(pipes[j][1], 1) < 0) Q(6, "dup2 failure - bailing");
      close(pipes[j][1]);       //wr->[1]=stdout; Par reads from pipes[j][0]
      runProgram(j); exit(0); } //Exit avoids multiple stupid TRAILER!!!
    else {                      //fork: In Parent
      kids[j] = kid;
      close(pipes[j][1]);       //kid will write to this side of pipe
      fds[j].fd = pipes[j][0]; fds[j].events = POLLIN; } }
  int nLive = jobs;             // // // MAIN KID DRIVING LOOP // // //
  while (nLive > 0) {                   //While our kids live, poll for their..
    if (poll(fds, jobs, -1) <= 0) {     //..pipes having data, then copy what..
      if (errno == EINTR) continue;     //..they write to parent stdout.
      Q(7, "poll(): %s (%d)\n", strerror(errno), errno); }
    for (j = 0; j < jobs; j++) {
#define cp1 /* Write already read header `rec` & then cp varLen data */ \
  dLen  = (rec.datLen[0] << 16) | rec.datLen[1];  /* Calc dLen & size */ \
  bytes = rec.nmLen + !!(rec.nmLen%2) + dLen + !!(dLen%2); \
  wD(&rec, sizeof rec);                 /* Send header to stdout */ \
  BufSize(&buf, bytes);                 /* Read all, blocking as needed */ \
  while ((nR = read(fds[j].fd, buf.p, bytes)) < 0) usleep(250); \
  wD(buf.p, bytes)                      //Send body to stdout
      if (fds[j].fd != -1 && fds[j].revents != 0) {
        if ((fds[j].revents & POLLIN) != 0) {               //Data is ready
          if ((nR = read(fds[j].fd, &rec, sizeof rec)) > 0) { cp1; }
          else {                //Do not ignore close failures here since..
            nLive--;            //.. .fd != -1 is used to control flow.
            if (close(fds[j].fd)==0) fds[j].fd = -1;
            else Q(8, "close: %s (%d)", strerror(errno), errno); } }
        if ((fds[j].revents & POLLHUP) != 0) {              //Kid is done
          while ((nR = read(fds[j].fd, &rec, sizeof rec) > 0)) { cp1; }
          nLive--;
          if (close(fds[j].fd)==0) fds[j].fd = -1;
          else Q(9, "close: %s (%d)", strerror(errno), errno); } } } }
  for (int j=0; j<jobs; j++) waitpid(kids[j],&x,0);}// make getrusage cumulative

void addDirents() {     // readdir("."), appending $dir/[1-9]* to av[], ac
  struct dirent *de;            // Should perhaps someday take a more..
  DIR *dp = opendir(".");       //..general pattern than this [1-9]*.
  if (!dp) Q(5, "opendir: %s (%d)", strerror(errno), errno);
  char **av2 = malloc((ac + 1)*sizeof av[0]);   // Copy of av[] to extend
  memcpy(av2, av, (ac + 1)*sizeof av[0]);
  av = av2;                     //Replace global with copy
  while ((de = readdir(dp)))    //Scan "." directory, keep only numeric dirs
    if (de->d_type == DT_DIR && de->d_name[0] >= '1' && de->d_name[0] <= '9') {
      av = realloc(av, (ac + 2)*sizeof av[0]);
      av[ac++] = strdup(de->d_name); } //Memory for av[] & av is intentionally..
  closedir(dp); }                      //..leaked; Reaped by OS. gcc-san misses?

#define A (av[i])               //Current CL A)rgument C-string
int main(int _ac, char **_av) {
  char *dir = getenv("d") ? getenv("d") : "/proc";
  ac = _ac; av = _av;           //Users: addDirents & runProgram(& so driveKids)
  if (ac < 2 || !*av[1] || av[1][0]=='-') quit(1, Use);
  thisUid = getuid();           //Short circuits some attempted /proc accesses
  if (chdir(dir)) { Q(2, "uid %d: cd %s: %s\n", thisUid, dir, strerror(errno));}
  for (i = 1; i < ac; i++) {    //Split av into pre-Program GLOBALS & Program..
    if (A[0]=='-' && A[1]=='-' && A[2]=='\0') { soProg = ++i; break; } //"--"
    if (A[0] != '\0') Aread(A, &st); }  //..archiving GLOBALS as we go.
  if (soProg >= ac) soProg = ac - 1;
  if (av[soProg][0] != 's') E("PROGRAM doesn't start w/\"s\"tat\n");
  for (/**/; i < ac; i++) {     //Split av into Program&explicit top-level list.
    if (A[0]=='-' && A[1]=='-' && A[2]=='\0') break;    //"--"
    if (A[0]=='\0' || A[1] != '/' || !(A[0]=='s' || A[0]=='r' || A[0]=='R'))
      Q(4, "bad command \"%s\" (not [srR]/XX)\n", A); } //Check Program
  eoProg = i > soProg ? i : soProg; //Ensure Program len >= 0
  if (eoProg <= soProg) E("No PROGRAM; Start(%d) >= End(%d))\n", eoProg,soProg);
  else {
    if (i < ac) i++;            //Skip "--" for next for(/**/; i < ac; i++) loop
    if (i == ac) addDirents();  //No top-level given => readdir to get it
    if ((jobs = getenv("j") ? atoi(getenv("j")) : -1)<=0) {  //Make j relative..
      jobs += sysconf(_SC_NPROCESSORS_ONLN);                 //..to nproc. 0=all
      if (jobs < 0) jobs = 1; }                              //..but -1 best.
    if (jobs == 1) runProgram(0);   // All set up - runProgram in this process..
    else driveKids(); }             //..or in `jobs` kids w/parent sequencer.
  memset(&rec,0,sizeof rec); rec.magic=0070707; rec.nlink=1; wH("TRAILER!!!",0);
/*if (buf.p) free(buf.p);*/ return 0; }
