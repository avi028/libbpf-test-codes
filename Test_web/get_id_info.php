<?php
class Id_data{
        public $id=0;
        public $name="";
        public $age=0;
    }
    $name_list = array("John Wick","Alan Tuning","Grace Hopper","Marie Curie","Albert Einstien","Issac Newton","Richard Fynmen","Ramanujan","CV Raman");
    $data = new Id_data();
    $data->id = rand(1000,1200);
    $data->name = $name_list[rand(1,8)];
    $data->age = rand(10,100);
    $final_Data = json_encode($data);
    echo $final_Data;
?>
