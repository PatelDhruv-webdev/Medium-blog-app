import { Hono } from "hono";
import { PrismaClient } from '@prisma/client/edge';
import { withAccelerate } from '@prisma/extension-accelerate';
import { sign } from 'hono/jwt';
import { signupInput, signinInput } from "@100xdevs/medium-common";

export const userRouter = new Hono<{
    Bindings: {
        DATABASE_URL: string;
        JWT_SECRET: string;
    }
}>();

userRouter.post('/signup', async (c) => {
    console.log('Request Headers:', c.req.header); // Log headers
    console.log('Request Method:', c.req.method);  // Log method

    try {
        const body = await c.req.json();
        console.log('Request Body:', body); // Log body

        const { success, error } = signupInput.safeParse(body);
        if (!success) {
            console.error('Input validation failed:', error.format());
            c.status(400);
            return c.json({
                message: "Inputs not correct",
                errors: error.format()
            });
        }

        const prisma = new PrismaClient({
            datasourceUrl: c.env.DATABASE_URL,
        }).$extends(withAccelerate());

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { username: body.username },
        });

        if (existingUser) {
            console.error('User already exists:', existingUser);
            c.status(409);
            return c.json({ message: 'User already exists' });
        }

        // Create a new user
        const user = await prisma.user.create({
            data: {
                username: body.username,
                password: body.password, // Consider hashing passwords
                name: body.name
            }
        });

        const jwt = await sign({ id: user.id }, c.env.JWT_SECRET);
        console.log('User created:', user);

        return c.json({ token: jwt });

    } catch (e) {
        console.error('Error during signup process:', e);
        c.status(500);
        return c.json({ message: 'Internal server error' });
    }
});

userRouter.post('/signin', async (c) => {
    try {
        const body = await c.req.json();
        console.log('Signin Request Body:', body); // Log body

        const { success, error } = signinInput.safeParse(body);
        if (!success) {
            console.error('Input validation failed:', error.format());
            c.status(400);
            return c.json({
                message: "Inputs not correct",
                errors: error.format()
            });
        }

        const prisma = new PrismaClient({
            datasourceUrl: c.env.DATABASE_URL,
        }).$extends(withAccelerate());

        // Find user with matching username and password
        const user = await prisma.user.findFirst({
            where: {
                username: body.username,
                password: body.password, // Make sure to hash and compare passwords
            }
        });

        if (!user) {
            console.error('Incorrect credentials');
            c.status(403);
            return c.json({ message: "Incorrect credentials" });
        }

        const jwt = await sign({ id: user.id }, c.env.JWT_SECRET);
        console.log('User signed in:', user);

        return c.json({ token: jwt });

    } catch (e) {
        console.error('Error during signin process:', e);
        c.status(500);
        return c.json({ message: 'Internal server error'});
    }
});
