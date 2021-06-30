CC = cl.exe
CFLAGS = /c /TC /I includes
LINK = link.exe
NAME = loader.exe
LFLAGS = /MACHINE:x86 /OUT:$(NAME)

SRCS = src/main.c \
	   src/reader.c \
	   src/loader.c \
	   src/debug.c

OBJS = main.obj reader.obj loader.obj debug.obj

all:
	$(CC) $(CFLAGS) $(SRCS)
	$(LINK) $(OBJS) $(LFLAGS)

clean:
	del $(OBJS) /S /Q

fclean:
	del $(OBJS) /S /Q
	del $(NAME) /S /Q