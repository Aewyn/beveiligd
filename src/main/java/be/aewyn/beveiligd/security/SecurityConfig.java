package be.aewyn.beveiligd.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {
    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNIER = "magazijnier";
    private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public JdbcUserDetailsManager maakPrincipals(){
        var manager = new JdbcUserDetailsManager(dataSource); // Je definieert met de bean dat een database principals bevat. Je geeft de DataSource mee die gebaseerd is op application.properties.
        // Spring Security zoekt de principals in de database die bij de DataSource hoort. IntelliJ kan op deze regel een foutmelding tonen die onterecht is.

        manager.setUsersByUsernameQuery("""
                select naam as username, paswoord as password, actief as enabled
                from gebruikers where naam = ?
                """);
        //Dit SQL statement leest één gebruiker aan de hand van de gebruikersnaam dia als param mee binnenkomt. Het statement geeft max 1 rij terug met 3 kolommen

        manager.setAuthoritiesByUsernameQuery("""
                select gebruikers.naam as username, rollen.naam as authorities
                from gebruikers
                inner join gebruikersrollen on gebruikers.id = gebruikersrollen.gebruikerId
                inner join rollen on rollen.id = gebruikersrollen.rolId
                where gebruikers.naam = ?
                """);
        //Dit SQL statement leest de authorities van één gebruiker adhv een gebruikersnaam die als param binnenkomt. Dit statement geeft een rij terug per authority met 2 kolommen

        return manager;
    }

//Onderstaande code is vervangen door bovenstaande bean
//    @Bean
//    public InMemoryUserDetailsManager maakPrincipals() {
//        //    Deze method geeft een InMemoryUserDetailsManager bean terug.
//        //    Je maakt daarmee principals in het RAM geheugen.
//        //    Spring maakt dan zelf geen gebruiker met de naam user meer.
//        var joe = User.withUsername("joe") //Je maakt een principal met de username Joe
//                .password("{noop}theboss") //Je maakt een paswoord theboss, {noop} betekent dat het pw niet geëncrypteerd is
//                .authorities(MANAGER) //Je geeft de authority manager
//                .build();
//        var averell = User.withUsername("averell")
//                .password("{noop}hungry")
//                .authorities(HELPDESKMEDEWERKER, MAGAZIJNIER)
//                .build();
//        return new InMemoryUserDetailsManager(joe, averell);
//    }

    @Bean
    public SecurityFilterChain geefRechten(HttpSecurity http) throws Exception {
        //    Je configureert daarmee toegangsrechten van de principals tot URL’s.
        //    IntelliJ kan op deze regel een foutmelding tonen die onterecht is.
        http.formLogin(login -> login.loginPage("/login")); // De gebruiker authenticeert zich door zijn naam en paswoord in te typen in een HTML form
        http.authorizeRequests(requests -> requests
                .mvcMatchers("/images/**", "/css/**", "/js/**").permitAll() // Spring Security moet geen beveiliging doen op URL's die passen bij /images/** (** betekent alle subfolders)
                .mvcMatchers("/offertes/**").hasAuthority(MANAGER) // Enkel gebruikers met de authority manager mogen naar de URL offertes en diens subfolders
                .mvcMatchers("/werknemers/**").hasAnyAuthority(MAGAZIJNIER, HELPDESKMEDEWERKER) // Enkel gebruikesr met de authorities magazijnier of helpdeskmedewerker mode naar de URL werknemers en subfolders
                .mvcMatchers("/", "/login").permitAll() // Je geeft alle gebruikers toegang tot de welkompagina en de loginpagina
                .mvcMatchers("/**").authenticated()); // Voor alle anders URL's moet de gebruiker minstens ingelogd zijn
//        De volgorde waarin je mvcMatchers oproept is belangrijk. Eerste specifieke url's zonder wildcards, dan de algemene url's met wildcards. Spring overloopt de url patronen in de volgorde dat je ze maakt
        http.logout(logout -> logout.logoutSuccessUrl("/")); // Spring voegt een functie toe om uit te loggen als er een POST wordt gestuurd naar /logout, in de lambda wijzig je de pagina die wordt getoond na goed uitloggen
        return http.build();
    }

    // Je ziet in de code twee keer .build(). Dit is een gebruik van het builder design pattern.
}
