package be.aewyn.beveiligd.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("werknemers")
public class WerknemerController {
    @GetMapping
    public String werknemers(){
        return "werknemers";
    }

}
