void initConst();
void initRule(struct rule *item);
int writeCtrlInfo(int size);
int readRuleInfo();
int insertRule(int len);
int appendRule(int len);
int deleteRule(int index);
int flushRule();
int setDefaultRule(int utarget);
void display(struct rule *item);