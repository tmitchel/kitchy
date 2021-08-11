CREATE TABLE users (
    user_id VARCHAR(64) PRIMARY KEY,
    user_name VARCHAR(100),
    user_password VARCHAR(100)
);

CREATE TABLE pantries (
    pantry_id VARCHAR(64) PRIMARY KEY,
    pantry_name VARCHAR(100)
);

CREATE TABLE recipes (
    recipe_id VARCHAR(64) PRIMARY KEY,
    recipe_name VARCHAR(100)
);

CREATE TABLE ingredients (
    ing_id VARCHAR(64) PRIMARY KEY,
    ing_name VARCHAR(100),
    calories INT,
    carbs INT,
    fat INT,
    protein INT
);

CREATE TABLE users_pantries (
    user_id VARCHAR(64) REFERENCES users(user_id) ON UPDATE CASCADE ON DELETE CASCADE,
    pantry_id VARCHAR(64) REFERENCES pantries(pantry_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE pantries_recipes (
    pantry_id VARCHAR(64) REFERENCES pantries(pantry_id) ON UPDATE CASCADE ON DELETE CASCADE,
    recipe_id VARCHAR(64) REFERENCES recipes(recipe_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE pantries_ingredients (
    pantry_id VARCHAR(64) REFERENCES pantries(pantry_id) ON UPDATE CASCADE ON DELETE CASCADE,
    ing_id VARCHAR(64) REFERENCES ingredients(ing_id) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE recipes_ingredients (
    recipe_id VARCHAR(64) REFERENCES recipes(recipe_id) ON UPDATE CASCADE ON DELETE CASCADE,
    ing_id VARCHAR(64) REFERENCES ingredients(ing_id) ON UPDATE CASCADE ON DELETE CASCADE
);
