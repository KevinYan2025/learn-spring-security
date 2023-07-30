package com.example.learnspringsecurity;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class HelloWorld {
    @GetMapping("/todo")
    public List<Todo> retrieveAllTodos(){
        return List.of(new Todo("kevin","learn aws"));
    }
    @GetMapping("/users/{username}/todo")
    public Todo retrieveTodo(@PathVariable String username){
        return new Todo(username,"learn aws");
    }
    @PostMapping("/users/{username}/todo")
    public Todo createTodo(@PathVariable String username, @RequestBody Todo todo){
       return new Todo(todo.username(),todo.description());
    }
    @GetMapping("csrf-token")
    public CsrfToken retrieveCsrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }

}
record Todo (String username,String description){};