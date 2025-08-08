#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define WIDTH  40
#define HEIGHT 20
#define ALIVE  'O'
#define DEAD   ' '

void initialize(int grid[HEIGHT][WIDTH]) {
    for (int y = 0; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            grid[y][x] = rand() % 2;
}

void print_grid(int grid[HEIGHT][WIDTH]) {
    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++)
            putchar(grid[y][x] ? ALIVE : DEAD);
        putchar('\n');
    }
}

int count_neighbors(int grid[HEIGHT][WIDTH], int y, int x) {
    int count = 0;
    for (int dy = -1; dy <= 1; dy++)
        for (int dx = -1; dx <= 1; dx++) {
            if (dy == 0 && dx == 0)
                continue;
            int ny = (y + dy + HEIGHT) % HEIGHT;
            int nx = (x + dx + WIDTH) % WIDTH;
            count += grid[ny][nx];
        }
    return count;
}

void next_generation(int grid[HEIGHT][WIDTH]) {
    int new_grid[HEIGHT][WIDTH] = {0};
    for (int y = 0; y < HEIGHT; y++) {
        for (int x = 0; x < WIDTH; x++) {
            int neighbors = count_neighbors(grid, y, x);
            if (grid[y][x]) {
                new_grid[y][x] = (neighbors == 2 || neighbors == 3);
            } else {
                new_grid[y][x] = (neighbors == 3);
            }
        }
    }
    for (int y = 0; y < HEIGHT; y++)
        for (int x = 0; x < WIDTH; x++)
            grid[y][x] = new_grid[y][x];
}

void clear_screen() {
    printf("\033[H\033[J");
}

int main(int argc, char **argv) {
    int grid[HEIGHT][WIDTH] = {0};
    srand(time(NULL));
    initialize(grid);
    for (int i = 0; i < 1000; i++) {
        clear_screen();
        print_grid(grid);
        next_generation(grid);
        usleep(100000); // sleep for 100ms
    }
    return 0;
}
