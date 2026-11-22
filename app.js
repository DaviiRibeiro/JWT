/* imports */
require('dotenv').config();
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config JSON response
app.use(express.json())

//models
const User = require('./models/User')

// open route - public route
app.get('/' , (req , res)=>{
    res.status(200).json({msg: "Welcome to the API"})
})
function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token= authHeader && authHeader.split(" ")[1]
    if(!token){
        return res.status(401).json({msg: "Acesso negado!"})
    }   
    try{
        const secret = process.env.SECRET
        jwt.verify(token , secret)
        next()
    }catch(error){
        res.status(400).json({msg: "Token inválido!"})
    }
}


//register
app.post('/auth/register' , async (req , res)=>{
    const {name , email, password, confirmpassword} = req.body

    //validations
    if(!name){
        return res.status(422).json({msg: "o nome é obrigatório!"})
    }
    if(!email){
        return res.status(422).json({msg: "o email é obrigatório!"})
    }
    if(!password){
        return res.status(422).json({msg: "a senha é obrigatória!"})
    }
    if(password !== confirmpassword){
        return res.status(422).json({msg: "as senhas não conferem!"})
    }

    //check if user exists
    const UserExists = await User.findOne({email: email})
    if(UserExists){
        return res.status(422).json({msg: "o email já está em uso!"})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try{
        await user.save()
        return res.status(201).json({msg: "Usuário criado com sucesso!"})
    }catch(err){
        return res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"})
    }
})
//login
app.post('/auth/login' , async (req , res)=>{
    const {email, password} = req.body

    if(!email){
        return res.status(422).json({msg: "o email é obrigatório!"})
    }
    if(!password){
        return res.status(422).json({msg: "a senha é obrigatória!"})
    }

    const user = await User.findOne({email: email})
    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado!"})
    }

    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({msg: "Senha inválida!"})
    }

    try{
        const secret = process.env.SECRET
        const token = jwt.sign(
            { id: user._id },
            secret
        )
        return res.status(200).json({msg: "Autenticação realizada com sucesso!", token})
    }catch(err){
        return res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"})
    }
})


//credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.PASSWORD

// private route
app.get('/user/:id',checkToken, async(req,res)=>{
    const id = req.params.id

    //check if user exists
    try{
        const user = await User.findById(id , '-password')
        if(!user){
            return res.status(404).json({msg: "Usuário não encontrado!"})
        }
        return res.status(200).json(user)
    }catch(err){
        return res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"})
    }
})

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.b5epbjr.mongodb.net/?appName=Cluster0`).then(()=>{
    app.listen(3000)
    console.log('Conectou com o banco de dados!')
}).catch((err) => console.log(err))