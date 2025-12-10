#ifndef USER_AUTH_H
#define USER_AUTH_H

int verify_user(const char *id, const char *pw);
void load_users();

#endif
