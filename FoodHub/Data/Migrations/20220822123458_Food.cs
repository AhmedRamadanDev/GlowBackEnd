using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FoodHub.Data.Migrations
{
    public partial class Food : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClientId",
                table: "diets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "diets",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "Foods",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Meal = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    dietId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Foods", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Foods_diets_dietId",
                        column: x => x.dietId,
                        principalTable: "diets",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateIndex(
                name: "IX_Foods_dietId",
                table: "Foods",
                column: "dietId");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Foods");

            migrationBuilder.DropColumn(
                name: "ClientId",
                table: "diets");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "diets");
        }
    }
}
