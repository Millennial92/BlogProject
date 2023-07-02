package com.example.blogproject.repository;

import com.example.blogproject.model.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

   @Repository
   public interface PostRepository extends JpaRepository<Post, Long> {

   }

